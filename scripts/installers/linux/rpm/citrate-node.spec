Name:           citrate-node
Version:        0.1.0
Release:        1%{?dist}
Summary:        Citrate AI-native Layer-1 blockchain node
License:        Apache-2.0
URL:            https://citrate.ai
Source0:        citrate-node-%{version}.tar.gz

BuildRequires:  gcc, openssl-devel
Requires:       openssl-libs

%description
Citrate is an AI-native Layer-1 BlockDAG blockchain using GhostDAG
consensus, paired with an EVM-compatible execution environment and
a standardized Model Context Protocol (MCP) layer. This package
installs the citrate-node daemon, CLI tools, and systemd service units.

%prep
%setup -q

%build
# Binary is pre-compiled via cargo build --release

%install
rm -rf %{buildroot}

# Binary
install -Dm755 target/release/citrate %{buildroot}/usr/bin/citrate
install -Dm755 target/release/citrate-wallet %{buildroot}/usr/bin/citrate-wallet
install -Dm755 target/release/citrate-cli %{buildroot}/usr/bin/citrate-cli

# Systemd units
install -Dm644 scripts/installers/linux/systemd/citrate-node.service %{buildroot}/usr/lib/systemd/system/citrate-node.service
install -Dm644 scripts/installers/linux/systemd/citrate-ipfs.service %{buildroot}/usr/lib/systemd/system/citrate-ipfs.service

# Config
install -Dm644 config/institutional_rewards.toml %{buildroot}/etc/citrate/institutional_rewards.toml

# Data directory
install -dm755 %{buildroot}/var/lib/citrate

# Curriculum model manifest (model file downloaded separately)
install -Dm644 models/curriculum/manifest.json %{buildroot}/usr/share/citrate/models/curriculum/manifest.json
install -Dm644 models/curriculum/system_prompt.txt %{buildroot}/usr/share/citrate/models/curriculum/system_prompt.txt

%pre
# Create citrate system user
getent group citrate >/dev/null || groupadd -r citrate
getent passwd citrate >/dev/null || useradd -r -g citrate -d /var/lib/citrate -s /sbin/nologin -c "Citrate node daemon" citrate

%post
# Set data directory ownership
chown -R citrate:citrate /var/lib/citrate

# Install and start services
systemctl daemon-reload
systemctl enable citrate-node.service
systemctl enable citrate-ipfs.service

echo "Citrate node installed. Start with: systemctl start citrate-node"

%preun
# Stop services before removal
systemctl stop citrate-node.service 2>/dev/null || true
systemctl stop citrate-ipfs.service 2>/dev/null || true
systemctl disable citrate-node.service 2>/dev/null || true
systemctl disable citrate-ipfs.service 2>/dev/null || true

%postun
systemctl daemon-reload
echo "Citrate removed. Data preserved at /var/lib/citrate"

%files
%license LICENSE
/usr/bin/citrate
/usr/bin/citrate-wallet
/usr/bin/citrate-cli
/usr/lib/systemd/system/citrate-node.service
/usr/lib/systemd/system/citrate-ipfs.service
%dir /etc/citrate
%config(noreplace) /etc/citrate/institutional_rewards.toml
%dir /var/lib/citrate
%dir /usr/share/citrate/models/curriculum
/usr/share/citrate/models/curriculum/manifest.json
/usr/share/citrate/models/curriculum/system_prompt.txt

%changelog
* Mon Mar 17 2026 Citrate Engineering <engineering@citrate.ai> - 0.1.0-1
- Initial RPM package for school node pilot
- Includes citrate-node, citrate-wallet, citrate-cli
- Systemd service units for node and IPFS
- Pre-loaded curriculum model manifest
