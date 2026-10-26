#!/usr/bin/env bash
# producer_baseline.sh: idempotent OS baseline for a Citrate producer host.
#
# Prepares a fresh Ubuntu 22.04+ host for the producer runbook
# (docs/ops/PRODUCER_OPERATOR_RUNBOOK.md, sections 1 and 2) WITHOUT installing or
# starting a node and WITHOUT creating any key. Safe to re-run at any time,
# including on a host whose node is already running: it never enables, starts,
# stops, disables or restarts citrate-node, and it never replaces a
# citrate-node unit that differs from its own template (the operator's
# gen_node_config.py output wins).
#
# Usage (as root on the host, or piped over ssh):
#   producer_baseline.sh apply      # converge the host, then run `check`
#   producer_baseline.sh check      # print the checklist; exit 1 on any FAIL
#   producer_baseline.sh print-unit         # the citrate-node unit template
#   producer_baseline.sh print-disk-alert   # the disk alert script it installs
#   producer_baseline.sh check-ufw-status < status   # verdict on `ufw status verbose`
#
#   ssh root@HOST 'bash -s -- apply' < scripts/ops/producer_baseline.sh
#
# What `apply` does:
#   - apt update/upgrade; unattended-upgrades (security origins only, no auto-reboot)
#   - `citrate` system user (no login shell), /var/lib/citrate/data (0700, owned by
#     citrate; the node mints its keys there) and /etc/citrate: the runbook layout.
#     Empty /opt/citrate dirs from an earlier layout are removed with rmdir only.
#   - journald capped (SystemMaxUse=1G, SystemKeepFree=10G); logrotate size cap
#     (maxsize 200M) run hourly. Two chain halts came from a full disk.
#   - 4 GiB swapfile, vm.swappiness=10
#   - chrony time sync
#   - sshd: keys only, PermitRootLogin prohibit-password, no passwords
#   - ufw as runbook section 2: deny incoming, allow outgoing, allow 22/tcp and
#     30303/tcp+udp (SSH is allowed BEFORE ufw is enabled). RPC/metrics stay closed.
#   - DigitalOcean monitoring agent (verified; installed if missing)
#   - citrate-disk-alert.timer: every 5 min, logs at crit and fails its unit when
#     any watched filesystem is at or above 80% used. Local logging only.
#   - citrate-node.service template (identical to gen_node_config.py's unit for the
#     default paths), installed DISABLED and not started.
#
# Not done here, on purpose: the node binary, node.toml, the consensus env, and
# every key.
set -euo pipefail

SWAP_FILE=/swapfile
SWAP_SIZE_MIB=4096
SWAPPINESS=10
DISK_ALERT_PCT=80
UNIT_PATH=/etc/systemd/system/citrate-node.service
CHANGED=()

die() { echo "producer_baseline: $*" >&2; exit 2; }
note() { echo "  - $*"; }

# ---- templates -------------------------------------------------------------

# Must stay byte-identical to render_unit("/etc/citrate", "/var/lib/citrate/data",
# "/usr/local/bin/citrate-node") in scripts/producers/gen_node_config.py.
# scripts/ops/tests/test_producer_baseline.py enforces this.
unit_template() {
  cat <<'EOF'
[Unit]
Description=Citrate node (producer)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=citrate
Group=citrate
EnvironmentFile=/etc/citrate/citrate-node.env
ExecStart=/usr/local/bin/citrate-node --config /etc/citrate/node.toml
Restart=always
RestartSec=5s
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/citrate/data
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
}

disk_alert_script() {
  cat <<'EOF'
#!/usr/bin/env bash
# citrate-disk-alert: log loudly when a watched filesystem reaches the threshold.
# Installed by scripts/ops/producer_baseline.sh. Exit 1 while any path is over the
# threshold, so `systemctl --failed` shows it too. Local logging only, no paging.
#   CITRATE_DISK_ALERT_PCT     threshold in percent used (default 80)
#   CITRATE_DISK_ALERT_PATHS   space-separated paths (default: / and the data dirs)
#   CITRATE_DISK_ALERT_SYSLOG  0 to skip logger (tests)
set -uo pipefail
PCT="${CITRATE_DISK_ALERT_PCT:-80}"
PATHS="${CITRATE_DISK_ALERT_PATHS:-/ /var/lib/citrate/data}"
case "$PCT" in ''|*[!0-9]*) echo "citrate-disk-alert: bad threshold '$PCT'" >&2; exit 2 ;; esac
rc=0
seen=" "
for p in $PATHS; do
  [ -e "$p" ] || continue
  line="$(df -P -- "$p" 2>/dev/null | awk 'NR==2 {print $6, $5}')" || line=""
  if [ -z "$line" ]; then
    echo "citrate-disk-alert: UNKNOWN cannot read usage of $p" >&2; rc=1; continue
  fi
  mnt="${line% *}"; used="${line##* }"; used="${used%\%}"
  case "$seen" in *" $mnt "*) continue ;; esac
  seen="$seen$mnt "
  if [ "$used" -ge "$PCT" ]; then
    msg="DISK ALERT: $mnt is ${used}% used (threshold ${PCT}%). A full disk has halted the chain before: free space now."
    echo "$msg" >&2
    if [ "${CITRATE_DISK_ALERT_SYSLOG:-1}" != 0 ]; then
      logger -p user.crit -t citrate-disk-alert -- "$msg" || true
    fi
    rc=1
  else
    echo "citrate-disk-alert: ok $mnt ${used}% used (threshold ${PCT}%)"
  fi
done
exit "$rc"
EOF
}

# ---- helpers ---------------------------------------------------------------

# put_file PATH MODE OWNER:GROUP  (content on stdin). Writes only when it differs.
put_file() {
  local path="$1" mode="$2" owner="$3" tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
  else
    install -D -m "$mode" -o "${owner%:*}" -g "${owner#*:}" "$tmp" "$path"
    rm -f "$tmp"
    CHANGED+=("$path")
  fi
  chmod "$mode" "$path"
  chown "$owner" "$path"
}

apt_noninteractive() {
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get -y \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

# ---- apply -----------------------------------------------------------------

apply_packages() {
  echo "[packages]"
  # needrestart must never bounce the producer after a library update.
  put_file /etc/needrestart/conf.d/50-citrate.conf 0644 root:root <<'EOF'
# producer_baseline.sh: never restart the producer from needrestart.
$nrconf{override_rc}{qr(^citrate-node)} = 0;
$nrconf{override_rc}{qr(^citrate-height-watchdog)} = 0;
EOF
  apt_noninteractive update -q >/dev/null
  apt_noninteractive upgrade -q
  apt_noninteractive install -q unattended-upgrades chrony logrotate ufw jq curl python3 >/dev/null
  note "packages upgraded; unattended-upgrades chrony logrotate ufw jq curl python3 present"
}

apply_unattended() {
  echo "[unattended-upgrades]"
  put_file /etc/apt/apt.conf.d/20auto-upgrades 0644 root:root <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  # Ubuntu's 50unattended-upgrades already limits origins to -security (and ESM);
  # this file pins the reboot policy and refuses -updates/-proposed/-backports.
  put_file /etc/apt/apt.conf.d/52citrate-unattended 0644 root:root <<'EOF'
// producer_baseline.sh: security updates only; never reboot a producer by itself.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
  systemctl enable --now unattended-upgrades.service >/dev/null 2>&1
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
  note "security-only, Automatic-Reboot false"
}

apply_user_dirs() {
  echo "[user and dirs]"
  if ! getent group citrate >/dev/null; then groupadd --system citrate; fi
  if ! id -u citrate >/dev/null 2>&1; then
    # Same command as runbook section 2.
    useradd --system --gid citrate --home-dir /var/lib/citrate --create-home \
      --shell /usr/sbin/nologin citrate
    CHANGED+=("user citrate")
  fi
  install -d -o citrate -g citrate -m 0755 /var/lib/citrate
  install -d -o citrate -g citrate -m 0700 /var/lib/citrate/data
  install -d -o root -g root -m 0755 /etc/citrate
  note "citrate uid $(id -u citrate); /var/lib/citrate/data 0700 (contents never read)"
  cleanup_legacy_opt
}

# An earlier revision also created /opt/citrate/{bin,data,keys}. Remove them only
# while they are empty: rmdir refuses a non-empty directory, so nothing is lost.
cleanup_legacy_opt() {
  [ -d /opt/citrate ] || return 0
  local d
  for d in bin data keys; do
    if [ -d "/opt/citrate/$d" ] && [ ! -L "/opt/citrate/$d" ] && [ -z "$(ls -A "/opt/citrate/$d")" ]; then
      rmdir "/opt/citrate/$d" && CHANGED+=("rmdir /opt/citrate/$d")
    fi
  done
  if [ -z "$(ls -A /opt/citrate)" ]; then
    rmdir /opt/citrate && CHANGED+=("rmdir /opt/citrate")
  else
    note "/opt/citrate is not empty: left in place ($(ls -A /opt/citrate | tr '\n' ' '))"
  fi
}

apply_logs() {
  echo "[journald and logrotate]"
  put_file /etc/systemd/journald.conf.d/citrate.conf 0644 root:root <<'EOF'
# producer_baseline.sh: a log flood must not fill the disk (two chain halts did).
[Journal]
SystemMaxUse=1G
SystemKeepFree=10G
SystemMaxFileSize=128M
RuntimeMaxUse=256M
EOF
  if [[ " ${CHANGED[*]-} " == *" /etc/systemd/journald.conf.d/citrate.conf "* ]]; then
    systemctl restart systemd-journald
  fi
  # A global default before the include applies to every /etc/logrotate.d entry
  # (rsyslog's /var/log/syslog grew to 51 GB once). Run hourly so maxsize bites.
  if ! grep -qE '^[[:space:]]*maxsize[[:space:]]' /etc/logrotate.conf; then
    sed -i '0,/^include \/etc\/logrotate.d/s//# producer_baseline.sh: rotate any log past 200M on the hourly run\nmaxsize 200M\n\n&/' /etc/logrotate.conf
    CHANGED+=("/etc/logrotate.conf")
  fi
  put_file /etc/logrotate.d/citrate 0644 root:root <<'EOF'
# producer_baseline.sh: any file logs the node or its tools write outside journald.
/var/log/citrate/*.log {
    hourly
    maxsize 100M
    rotate 24
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
  put_file /etc/systemd/system/logrotate.timer.d/citrate.conf 0644 root:root <<'EOF'
# producer_baseline.sh: hourly so the maxsize cap takes effect within an hour.
[Timer]
OnCalendar=
OnCalendar=hourly
AccuracySec=1m
EOF
  systemctl daemon-reload
  systemctl enable --now logrotate.timer >/dev/null 2>&1
  note "journald 1G cap; logrotate maxsize 200M hourly"
}

apply_swap() {
  echo "[swap]"
  if ! swapon --show=NAME --noheadings | grep -qx "$SWAP_FILE"; then
    if [ ! -f "$SWAP_FILE" ]; then
      fallocate -l "${SWAP_SIZE_MIB}M" "$SWAP_FILE"
      chmod 0600 "$SWAP_FILE"
      mkswap "$SWAP_FILE" >/dev/null
      CHANGED+=("$SWAP_FILE")
    fi
    chmod 0600 "$SWAP_FILE"
    swapon "$SWAP_FILE"
  fi
  if ! grep -qE "^$SWAP_FILE[[:space:]]" /etc/fstab; then
    echo "$SWAP_FILE none swap sw 0 0" >>/etc/fstab
    CHANGED+=("/etc/fstab")
  fi
  put_file /etc/sysctl.d/60-citrate.conf 0644 root:root <<EOF
# producer_baseline.sh: swap only under real memory pressure (OOM kills on 2 GB nodes).
vm.swappiness=$SWAPPINESS
EOF
  sysctl -q -p /etc/sysctl.d/60-citrate.conf
  note "$SWAP_FILE $(swapon --show=SIZE --noheadings "$SWAP_FILE" | tr -d ' '), swappiness $(cat /proc/sys/vm/swappiness)"
}

apply_time() {
  echo "[time]"
  systemctl enable --now chrony >/dev/null 2>&1
  timedatectl set-ntp true 2>/dev/null || true
  # Give chrony up to 60 s to reach a source on a fresh install.
  local i
  for i in $(seq 1 30); do
    if chronyc -n tracking 2>/dev/null | grep -q 'Leap status *: Normal'; then break; fi
    sleep 2
  done
  note "chrony $(systemctl is-active chrony)"
}

apply_ssh() {
  echo "[ssh]"
  # 10- sorts before cloud-init's 50-; sshd keeps the first value it reads.
  put_file /etc/ssh/sshd_config.d/10-citrate.conf 0644 root:root <<'EOF'
# producer_baseline.sh: keys only. Root keeps key access, like the rest of the fleet.
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PermitEmptyPasswords no
EOF
  sshd -t || die "sshd -t rejected the config; not reloading"
  if [[ " ${CHANGED[*]-} " == *" /etc/ssh/sshd_config.d/10-citrate.conf "* ]]; then
    systemctl reload ssh
  fi
  note "key-only"
}

# Runbook section 2. Rules first, enable last: an active ufw without the SSH rule
# would cut the session that is running this script.
apply_firewall() {
  echo "[firewall]"
  local before
  before="$(ufw status verbose 2>/dev/null || true)"
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw allow 22/tcp >/dev/null
  ufw allow 30303/tcp >/dev/null
  ufw allow 30303/udp >/dev/null
  ufw show added | grep -qx 'ufw allow 22/tcp' || die "ufw has no 22/tcp rule; not enabling"
  ufw --force enable >/dev/null
  if [ "$(ufw status verbose)" != "$before" ]; then CHANGED+=("ufw"); fi
  note "ufw $(ufw status | head -1 | awk '{print $2}'): 22/tcp, 30303/tcp+udp in"
}

# Reads `ufw status verbose` on stdin. Exit 0 only for the runbook policy: active,
# deny incoming, allow outgoing, and exactly 22/tcp + 30303/tcp + 30303/udp allowed.
ufw_status_ok() {
  local text line rule want
  text="$(cat)"
  grep -qx 'Status: active' <<<"$text" || { echo "ufw not active"; return 1; }
  grep -qE '^Default: deny \(incoming\), allow \(outgoing\)' <<<"$text" \
    || { echo "defaults are not deny incoming / allow outgoing"; return 1; }
  for want in 22/tcp 30303/tcp 30303/udp; do
    grep -qE "^${want}[[:space:]]+ALLOW IN[[:space:]]" <<<"$text" || { echo "$want not allowed in"; return 1; }
  done
  while IFS= read -r line; do
    rule="${line%%  *}"; rule="${rule% (v6)}"
    case "$rule" in
      22/tcp|30303/tcp|30303/udp) ;;
      *) echo "unexpected inbound rule: $line"; return 1 ;;
    esac
  done < <(grep -E '[[:space:]](ALLOW|LIMIT)( IN)?[[:space:]]' <<<"$text")
  return 0
}

apply_monitoring() {
  echo "[do monitoring]"
  if ! systemctl is-active --quiet do-agent; then
    # DigitalOcean's documented installer for the metrics agent.
    curl -fsSL --proto '=https' https://repos.insights.digitalocean.com/install.sh | bash
    CHANGED+=("do-agent")
  fi
  systemctl enable do-agent >/dev/null 2>&1 || true
  note "do-agent $(systemctl is-active do-agent)"
}

apply_disk_alert() {
  echo "[disk alert]"
  disk_alert_script | put_file /usr/local/sbin/citrate-disk-alert 0755 root:root
  put_file /etc/systemd/system/citrate-disk-alert.service 0644 root:root <<EOF
[Unit]
Description=Citrate disk usage alert (logs at crit at ${DISK_ALERT_PCT}% used)

[Service]
Type=oneshot
Environment=CITRATE_DISK_ALERT_PCT=${DISK_ALERT_PCT}
ExecStart=/usr/local/sbin/citrate-disk-alert
EOF
  put_file /etc/systemd/system/citrate-disk-alert.timer 0644 root:root <<'EOF'
[Unit]
Description=Run citrate-disk-alert every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now citrate-disk-alert.timer >/dev/null 2>&1
  systemctl start citrate-disk-alert.service || true
  note "timer $(systemctl is-active citrate-disk-alert.timer), threshold ${DISK_ALERT_PCT}%"
}

apply_unit_template() {
  echo "[citrate-node unit template]"
  if [ ! -e "$UNIT_PATH" ]; then
    unit_template | put_file "$UNIT_PATH" 0644 root:root
    systemctl daemon-reload
    note "installed $UNIT_PATH (disabled, not started)"
  elif unit_template | cmp -s - "$UNIT_PATH"; then
    note "template already installed; state left as is"
  else
    note "$UNIT_PATH differs from the template (operator unit): left alone"
  fi
}

do_apply() {
  [ "$(id -u)" -eq 0 ] || die "apply must run as root"
  [ -r /etc/os-release ] && . /etc/os-release
  [ "${ID:-}" = ubuntu ] || die "Ubuntu only (found ${ID:-unknown})"
  echo "== producer_baseline apply on $(hostname) =="
  apply_packages
  apply_unattended
  apply_user_dirs
  apply_logs
  apply_swap
  apply_time
  apply_ssh
  apply_firewall
  apply_monitoring
  apply_disk_alert
  apply_unit_template
  if [ "${#CHANGED[@]}" -eq 0 ]; then
    echo "changed: nothing (already converged)"
  else
    echo "changed: ${CHANGED[*]}"
  fi
  [ -f /var/run/reboot-required ] && echo "NOTE: reboot required for upgraded packages (not done automatically)"
  echo
  do_check
}

# ---- check -----------------------------------------------------------------

FAILS=0
row() { # STATUS ITEM DETAIL
  printf '%-5s %-22s %s\n' "$1" "$2" "$3"
  [ "$1" = FAIL ] && FAILS=$((FAILS + 1))
  return 0
}
ok_if() { # ITEM DETAIL CMD...
  local item="$1" detail="$2"; shift 2
  if "$@" >/dev/null 2>&1; then row PASS "$item" "$detail"; else row FAIL "$item" "$detail"; fi
}
stat_is() { [ "$(stat -c '%U:%G %a' "$1" 2>/dev/null)" = "$2" ]; }

do_check() {
  [ "$(id -u)" -eq 0 ] || die "check must run as root (sshd -T, stat)"
  echo "== producer_baseline check on $(hostname) ($(. /etc/os-release; echo "$PRETTY_NAME"), $(uname -m)) =="
  local v

  v="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ' || true)"
  if [ "$v" = 0 ]; then row PASS packages "no pending upgrades"; else row WARN packages "$v pending upgrades"; fi
  [ -f /var/run/reboot-required ] && row WARN reboot "reboot required for upgraded packages (not automatic)"
  ok_if unattended-upgrades "installed, periodic on" \
    sh -c 'dpkg -s unattended-upgrades | grep -q "Status: install ok installed" && apt-config dump | grep -q "APT::Periodic::Unattended-Upgrade \"1\""'
  ok_if uu-security-only "no -updates/-proposed/-backports origins" \
    sh -c '! apt-config dump | grep -A0 -E "^Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)::" | grep -E -- "-(updates|proposed|backports)"'
  ok_if uu-no-reboot "Automatic-Reboot false" \
    sh -c 'apt-config dump | grep -qx "Unattended-Upgrade::Automatic-Reboot \"false\";"'

  v="$(id -u citrate 2>/dev/null || echo none)"
  if [ "$v" != none ] && [ "$v" != 0 ] && [ "$(getent passwd citrate | cut -d: -f7)" = /usr/sbin/nologin ]; then
    row PASS user "citrate uid $v, nologin"
  else
    row FAIL user "citrate user missing, uid 0 or has a login shell ($v)"
  fi
  ok_if dir-var-data "/var/lib/citrate/data citrate 0700" stat_is /var/lib/citrate/data "citrate:citrate 700"
  ok_if dir-etc "/etc/citrate root 0755" stat_is /etc/citrate "root:root 755"
  if [ -e /opt/citrate ]; then
    row WARN legacy-opt "/opt/citrate still present (not empty): $(ls -A /opt/citrate | tr '\n' ' ')"
  else
    row PASS legacy-opt "no /opt/citrate (single layout)"
  fi

  v="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^SystemMaxUse=' | tail -1 || true)"
  if [ "$v" = "SystemMaxUse=1G" ]; then row PASS journald "$v, journal now $(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMGT]' | head -1)"; else row FAIL journald "effective '${v:-unset}'"; fi
  ok_if logrotate "maxsize 200M global, config parses" \
    sh -c 'grep -qE "^maxsize 200M" /etc/logrotate.conf && logrotate -d /etc/logrotate.conf'
  ok_if logrotate-timer "hourly, active" \
    sh -c 'systemctl is-active --quiet logrotate.timer && systemctl show logrotate.timer -p TimersCalendar | grep -qF "OnCalendar=*-*-* *:00:00 ;"'

  v="$(swapon --show=SIZE --noheadings "$SWAP_FILE" 2>/dev/null | tr -d ' ' || true)"
  if [ "$v" = 4G ] && grep -qE "^$SWAP_FILE[[:space:]]" /etc/fstab; then row PASS swap "$SWAP_FILE $v, in fstab"; else row FAIL swap "swapfile '${v:-off}' or not in fstab"; fi
  v="$(cat /proc/sys/vm/swappiness)"
  if [ "$v" = "$SWAPPINESS" ]; then row PASS swappiness "$v"; else row FAIL swappiness "$v"; fi

  ok_if chrony "active, enabled" sh -c 'systemctl is-active --quiet chrony && systemctl is-enabled --quiet chrony'
  v="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
  if [ "$v" = yes ]; then
    row PASS ntp-sync "synchronized ($(chronyc -n tracking 2>/dev/null | awk -F': ' '/System time/ {print $2}'))"
  else
    row FAIL ntp-sync "NTPSynchronized=${v:-unknown}"
  fi

  v="$(sshd -T 2>/dev/null | grep -E '^(passwordauthentication|permitrootlogin|kbdinteractiveauthentication|pubkeyauthentication) ' | sort | tr '\n' ' ' || true)"
  if [[ "$v" == *"kbdinteractiveauthentication no"* && "$v" == *"passwordauthentication no"* \
     && ( "$v" == *"permitrootlogin without-password"* || "$v" == *"permitrootlogin prohibit-password"* ) && "$v" == *"pubkeyauthentication yes"* ]]; then
    row PASS sshd "key-only, root by key (prohibit-password)"
  else
    row FAIL sshd "effective: $v"
  fi

  if v="$(ufw status verbose 2>/dev/null | ufw_status_ok)"; then
    row PASS firewall "ufw active; deny in, allow out; 22/tcp 30303/tcp 30303/udp only"
  else
    row FAIL firewall "${v:-ufw status unreadable}"
  fi
  ok_if ufw-enabled "ufw.service enabled at boot" systemctl is-enabled --quiet ufw

  ok_if do-agent "DO monitoring agent active, enabled" \
    sh -c 'systemctl is-active --quiet do-agent && systemctl is-enabled --quiet do-agent'

  ok_if disk-alert "timer active, threshold ${DISK_ALERT_PCT}%" \
    sh -c 'systemctl is-active --quiet citrate-disk-alert.timer && systemctl is-enabled --quiet citrate-disk-alert.timer && [ -x /usr/local/sbin/citrate-disk-alert ]'
  if CITRATE_DISK_ALERT_SYSLOG=0 /usr/local/sbin/citrate-disk-alert >/dev/null 2>&1; then
    row PASS disk-usage "$(df -P / | awk 'NR==2 {print $5}') of / used"
  else
    row WARN disk-usage "at or above ${DISK_ALERT_PCT}% on a watched path"
  fi

  if [ ! -e "$UNIT_PATH" ]; then
    row FAIL node-unit "$UNIT_PATH missing"
  elif unit_template | cmp -s - "$UNIT_PATH"; then
    local en act
    en="$(systemctl is-enabled citrate-node 2>/dev/null || true)"
    act="$(systemctl is-active citrate-node 2>/dev/null || true)"
    if [ "$en" = disabled ] && [ "$act" = inactive ]; then
      row PASS node-unit "template installed, disabled, not running"
    else
      row WARN node-unit "template installed but enabled=$en active=$act"
    fi
  else
    row INFO node-unit "operator unit in place (differs from template); not checked"
  fi
  if command -v citrate-node >/dev/null 2>&1 || [ -e /usr/local/bin/citrate-node ]; then
    row INFO node-binary "/usr/local/bin/citrate-node present"
  else
    row INFO node-binary "not installed (expected before the release)"
  fi

  echo "result: $([ "$FAILS" -eq 0 ] && echo PASS || echo "FAIL ($FAILS)")"
  [ "$FAILS" -eq 0 ]
}

case "${1:-}" in
  apply) do_apply ;;
  check) do_check ;;
  print-unit) unit_template ;;
  print-disk-alert) disk_alert_script ;;
  check-ufw-status) ufw_status_ok ;;
  *) echo "usage: $0 apply|check|print-unit|print-disk-alert|check-ufw-status" >&2; exit 2 ;;
esac
