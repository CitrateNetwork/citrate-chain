"""Runs the runbook's node install block (docs/ops/PRODUCER_OPERATOR_RUNBOOK.md §3)
against good and bad release fixtures.

The block is read from the runbook itself, so the test checks what an operator
pastes. Only the operator-filled assignments are substituted (tag, expected hash,
expected fingerprint, install dir). Everything runs under a fresh temporary
directory with HOME and TMPDIR inside it and a PATH holding only the tools the block
needs. `curl` and `cosign` are test fakes: curl serves files from a fixture dir;
cosign accepts a signature only when it names the SHA-256 of the blob it is given.
No network, nothing outside the temp dir is written."""

import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
RUNBOOK = REPO / "docs/ops/PRODUCER_OPERATOR_RUNBOOK.md"
DELIM = "INSTALL_CITRATE_NODE"
ARCH = "x86_64-unknown-linux-gnu"
TAG = "v0.0.0-test"
GOOD_FP = "0x" + "1f" * 16
TARBALL = f"citrate-chain-{ARCH}.tar.gz"
BASE = f"https://github.com/CitrateNetwork/citrate-chain/releases/download/{TAG}"
ISSUER = "https://token.actions.githubusercontent.com"
IDENTITY = (
    r"^https://github\.com/CitrateNetwork/citrate-chain/\.github/workflows/"
    r"(release|release-tier2)\.yml@refs/(heads/main|tags/v[0-9A-Za-z._-]+)$"
)
REAL_TOOLS = ["bash", "sha256sum", "cut", "mktemp", "rm", "mkdir", "tar", "gzip",
              "install", "cp", "mv", "cmp", "cat", "chmod", "ln"]
OLD_BINARY = b"#!/bin/sh\necho previously installed node\n"


def install_block() -> str:
    """The fenced bash block of the runbook that runs the install heredoc."""
    blocks = re.findall(r"```bash\n(.*?)```", RUNBOOK.read_text(), flags=re.S)
    hits = [b for b in blocks if b.startswith(f"bash <<'{DELIM}'\n")]
    if len(hits) != 1:
        raise AssertionError(f"expected exactly one install block, found {len(hits)}")
    return hits[0]


def fill(block: str, values: dict) -> str:
    for name, value in values.items():
        pat = re.compile(rf"^{name}='[^']*'(.*)$", re.M)
        if len(pat.findall(block)) != 1:
            raise AssertionError(f"{name}= must be assigned exactly once in the block")
        block = pat.sub(lambda m: f"{name}='{value}'{m.group(1)}", block)
    return block


TAMPERED = "#!/bin/sh\necho not the released node\n"

# What a fake release binary does while it runs for the fingerprint check, after it prints
# the good fingerprint. Each one changes a file the old block went on to install.
BEHAVIOURS = {
    "": "",
    # write new bytes into the file that is running
    "rewrite-self": f"printf '%s' '{TAMPERED}' > \"$0\"\n",
    # put another file (a new inode) at the path that is running
    "replace-self": f"printf '%s' '{TAMPERED}' > \"$0.x\"; chmod 755 \"$0.x\"; mv -f \"$0.x\" \"$0\"\n",
    # rewrite every citrate-node under the work dir (the cwd), copies included
    "rewrite-all": (
        'for f in "$PWD"/*/citrate-node "$PWD"/*/*/citrate-node; do\n'
        '  if [ -f "$f" ]; then chmod u+w "$f"; '
        f"printf '%s' '{TAMPERED}' > \"$f\"; fi\n"
        "done\n"
    ),
}


def fake_node(fp: str, behaviour: str = "") -> bytes:
    return (
        "#!/bin/bash\n"
        'echo "$*" >> "$FAKE_NODE_EXEC_LOG"\n'
        "echo '2026-10-19T00:00:00Z INFO citrate: config loaded'\n"
        f"printf '{{\\n  \"fingerprint\": \"{fp}\"\\n}}\\n'\n"
        # One brace group: bash parses it whole before it runs, so rewriting the running
        # script cannot cut it short.
        + (f"{{\n{BEHAVIOURS[behaviour]}exit 0\n}}\n" if behaviour else "")
    ).encode()


def make_tarball(fp: str, symlink: bool = False, behaviour: str = "", dir_link: str = "",
                 mode: int = 0o755, uid: int = 0, uname: str = "") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        name = f"citrate-chain-{ARCH}/citrate-node"
        if dir_link:
            info = tarfile.TarInfo(f"citrate-chain-{ARCH}")
            info.type = tarfile.SYMTYPE
            info.linkname = dir_link
            tf.addfile(info)
        elif symlink:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = "/bin/true"
            tf.addfile(info)
        else:
            data = fake_node(fp, behaviour)
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid, info.uname = uid, uname
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def sign(blob: bytes) -> bytes:
    return ("fixture-signature:" + hashlib.sha256(blob).hexdigest()).encode()


FAKE_CURL = r"""#!/bin/bash
# test fake: serves $FAKE_FIXTURES/<basename> for URLs under the release base only
echo "$*" >> "$FAKE_CURL_LOG"
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    --proto) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in "$FAKE_BASE"/*) ;; *) echo "fake curl: unexpected url $url" >&2; exit 22 ;; esac
src="$FAKE_FIXTURES/${url##*/}"
if [ ! -f "$src" ]; then echo "fake curl: 404 $url" >&2; exit 22; fi
cat "$src" > "$out"
"""

FAKE_COSIGN = """#!{py}
# test fake: accepts a signature only if it names the SHA-256 of the blob, with the
# release issuer and identity regexp the runbook pins.
import hashlib, sys
a = sys.argv[1:]
open(__import__("os").environ["FAKE_COSIGN_LOG"], "a").write(" ".join(a) + "\\n")
if not a or a[0] != "verify-blob":
    sys.exit(2)
blob = a[1]
opt = lambda k: a[a.index(k) + 1]
ok = (
    open(opt("--signature"), "rb").read()
    == b"fixture-signature:" + hashlib.sha256(open(blob, "rb").read()).hexdigest().encode()
    and opt("--certificate-oidc-issuer") == {issuer!r}
    and opt("--certificate-identity-regexp") == {identity!r}
)
print("Verified OK" if ok else "Error: none of the signatures verified", file=sys.stderr)
sys.exit(0 if ok else 1)
"""


class InstallBlockTest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="runbook-install-")
        self.t = Path(self._td.name).resolve()
        for d in ("home", "tmp", "bin", "fixtures", "install", "logs"):
            (self.t / d).mkdir()
        self.bin = self.t / "bin"
        for tool in REAL_TOOLS:
            path = shutil.which(tool)
            self.assertIsNotNone(path, f"{tool} is needed for this test")
            os.symlink(path, self.bin / tool)
        (self.bin / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        (self.bin / "curl").write_text(FAKE_CURL)
        (self.bin / "cosign").write_text(
            FAKE_COSIGN.format(py=sys.executable, issuer=ISSUER, identity=IDENTITY))
        for f in ("python3", "curl", "cosign"):
            (self.bin / f).chmod(0o755)
        self.install = self.t / "install"
        (self.install / "citrate-node").write_bytes(OLD_BINARY)
        (self.install / "citrate-node").chmod(0o755)
        self.publish(make_tarball(GOOD_FP))
        self.announced_sha = hashlib.sha256(self.tarball).hexdigest()
        self.announced_fp = GOOD_FP

    def tearDown(self):
        self._td.cleanup()

    def publish(self, tarball: bytes, sig: bytes = None):
        self.tarball = tarball
        fx = self.t / "fixtures"
        (fx / TARBALL).write_bytes(tarball)
        (fx / f"{TARBALL}.sig").write_bytes(sig if sig is not None else sign(tarball))
        (fx / f"{TARBALL}.pem").write_text("fixture certificate\n")

    def run_block(self, fill_values=True):
        block = install_block()
        if fill_values:
            block = fill(block, {
                "TAG": TAG,
                "ARCH": ARCH,
                "EXPECTED_SHA256": self.announced_sha,
                "EXPECTED_FINGERPRINT": self.announced_fp,
                "INSTALL_DIR": str(self.install),
            })
        else:
            block = fill(block, {"INSTALL_DIR": str(self.install)})
        # Host guard: the block that runs must not name any system install path.
        self.assertNotIn("/usr/local/bin", block)
        env = {
            "PATH": str(self.bin),
            "HOME": str(self.t / "home"),
            "TMPDIR": str(self.t / "tmp"),
            "LC_ALL": "C",
            "FAKE_BASE": BASE,
            "FAKE_FIXTURES": str(self.t / "fixtures"),
            "FAKE_CURL_LOG": str(self.t / "logs/curl"),
            "FAKE_COSIGN_LOG": str(self.t / "logs/cosign"),
            "FAKE_NODE_EXEC_LOG": str(self.t / "logs/node-exec"),
        }
        p = subprocess.run([str(self.bin / "bash"), "-c", block], cwd=self.t / "home",
                           env=env, capture_output=True, text=True, timeout=60)
        return p

    def log(self, name):
        f = self.t / "logs" / name
        return f.read_text().splitlines() if f.exists() else []

    def assert_refused(self, p, reason):
        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("REFUSED:", p.stderr)
        self.assertIn(reason, p.stderr)
        self.assertNotIn("INSTALLED", p.stdout)
        # The install dir is exactly as it was: the old binary, nothing new beside it.
        self.assertEqual(sorted(os.listdir(self.install)), ["citrate-node"])
        self.assertEqual((self.install / "citrate-node").read_bytes(), OLD_BINARY)
        self.assertEqual(os.listdir(self.t / "tmp"), [], "the work dir is removed on exit")

    # -- the block itself -------------------------------------------------------

    def test_block_is_fail_closed_by_construction(self):
        block = install_block()
        lines = block.splitlines()
        self.assertEqual(lines[1], "set -euo pipefail")
        self.assertEqual(lines[-1], DELIM)
        self.assertNotIn("||", block, "no `||` chaining in the install block")
        self.assertNotIn("curl -fsSLO", block)
        # The deploy script and the runbook pin the same signer identity.
        deploy = (REPO / "scripts/deploy_testnet.sh").read_text()
        self.assertIn(f"COSIGN_IDENTITY_RE='{IDENTITY}'", deploy)
        self.assertIn(f"IDENTITY='{IDENTITY}'", block)

    def test_good_release_installs_the_verified_binary(self):
        p = self.run_block()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(f"INSTALLED citrate-node {TAG}", p.stdout)
        with tarfile.open(fileobj=io.BytesIO(self.tarball)) as tf:
            member = tf.extractfile(f"citrate-chain-{ARCH}/citrate-node")
            expected = member.read()
        self.assertEqual((self.install / "citrate-node").read_bytes(), expected)
        self.assertEqual((self.install / "citrate-node.prev").read_bytes(), OLD_BINARY)
        self.assertFalse((self.install / "citrate-node.new").exists())
        self.assertEqual(self.log("node-exec"), ["consensus --json"])
        self.assertEqual(len(self.log("cosign")), 1)
        self.assertEqual(os.listdir(self.t / "tmp"), [])

    # -- each failure refuses ---------------------------------------------------

    def test_bad_sha256_refuses_before_signature_or_execution(self):
        self.announced_sha = hashlib.sha256(b"some other tarball").hexdigest()
        p = self.run_block()
        self.assert_refused(p, "tarball SHA-256")
        self.assertEqual(self.log("cosign"), [])
        self.assertEqual(self.log("node-exec"), [], "an unverified binary never runs")

    def test_tampered_tarball_refuses(self):
        # The announced hash is the genuine one; the server hands out another tarball
        # with a signature over that other tarball.
        self.publish(make_tarball("0x" + "66" * 16))
        p = self.run_block()
        self.assert_refused(p, "tarball SHA-256")
        self.assertEqual(self.log("node-exec"), [])

    def test_bad_signature_refuses_before_execution(self):
        self.publish(self.tarball, sig=sign(b"a different blob"))
        p = self.run_block()
        self.assert_refused(p, "cosign signature check failed")
        self.assertEqual(len(self.log("cosign")), 1)
        self.assertEqual(self.log("node-exec"), [], "an unsigned binary never runs")

    def test_bad_fingerprint_refuses(self):
        self.announced_fp = "0x" + "2e" * 16
        p = self.run_block()
        self.assert_refused(p, "consensus fingerprint")
        self.assertEqual(self.log("node-exec"), ["consensus --json"])

    def test_missing_cosign_refuses_before_download(self):
        (self.bin / "cosign").unlink()
        p = self.run_block()
        self.assert_refused(p, "cosign is not installed")
        self.assertEqual(self.log("curl"), [])

    def test_failed_download_refuses(self):
        (self.t / "fixtures" / f"{TARBALL}.sig").unlink()
        p = self.run_block()
        self.assert_refused(p, f"download of {TARBALL}.sig failed")
        self.assertEqual(self.log("cosign"), [])
        self.assertEqual(self.log("node-exec"), [])

    def test_symlinked_binary_in_signed_tarball_refuses(self):
        self.publish(make_tarball(GOOD_FP, symlink=True))
        self.announced_sha = hashlib.sha256(self.tarball).hexdigest()
        p = self.run_block()
        self.assert_refused(p, "symlink")
        self.assertEqual(self.log("node-exec"), [])

    # -- the installed file is the verified file -------------------------------

    def released_binary(self) -> bytes:
        with tarfile.open(fileobj=io.BytesIO(self.tarball)) as tf:
            return tf.extractfile(f"citrate-chain-{ARCH}/citrate-node").read()

    def publish_signed(self, tarball: bytes):
        self.publish(tarball)
        self.announced_sha = hashlib.sha256(self.tarball).hexdigest()

    def test_binary_that_rewrites_itself_while_checked_is_not_installed(self):
        self.publish_signed(make_tarball(GOOD_FP, behaviour="rewrite-self"))
        p = self.run_block()
        self.assert_refused(p, "changed during the fingerprint check")
        self.assertEqual(self.log("node-exec"), ["consensus --json"])

    def test_binary_that_replaces_itself_while_checked_is_not_installed(self):
        self.publish_signed(make_tarball(GOOD_FP, behaviour="replace-self"))
        p = self.run_block()
        self.assert_refused(p, "changed during the fingerprint check")

    def test_binary_that_rewrites_every_copy_while_checked_is_not_installed(self):
        self.publish_signed(make_tarball(GOOD_FP, behaviour="rewrite-all"))
        p = self.run_block()
        self.assert_refused(p, "changed during the fingerprint check")

    def test_release_directory_given_as_a_symlink_refuses(self):
        # The signed tarball's release directory points somewhere else, where a binary
        # with the announced fingerprint waits. Nothing outside the tarball is run or
        # installed.
        elsewhere = self.t / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "citrate-node").write_bytes(fake_node(GOOD_FP))
        (elsewhere / "citrate-node").chmod(0o755)
        self.publish_signed(make_tarball(GOOD_FP, dir_link=str(elsewhere)))
        p = self.run_block()
        self.assert_refused(p, "symlink")
        self.assertEqual(self.log("node-exec"), [])

    def test_symlinks_planted_at_the_install_side_paths_are_not_followed(self):
        victim = self.t / "victim"
        victim.write_bytes(b"untouched\n")
        for side in ("citrate-node.prev", "citrate-node.new"):
            os.symlink(victim, self.install / side)
        p = self.run_block()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(victim.read_bytes(), b"untouched\n")
        self.assertEqual((self.install / "citrate-node").read_bytes(), self.released_binary())
        prev = self.install / "citrate-node.prev"
        self.assertFalse(prev.is_symlink())
        self.assertEqual(prev.read_bytes(), OLD_BINARY)

    def test_release_file_mode_and_owner_are_not_carried_over(self):
        self.publish_signed(make_tarball(GOOD_FP, mode=0o6777, uid=4242, uname="mallory"))
        p = self.run_block()
        self.assertEqual(p.returncode, 0, p.stderr)
        st = os.lstat(self.install / "citrate-node")
        self.assertEqual(st.st_mode & 0o7777, 0o755)
        self.assertEqual(st.st_uid, os.geteuid())
        self.assertEqual((self.install / "citrate-node").read_bytes(), self.released_binary())

    def test_unfilled_placeholders_refuse(self):
        p = self.run_block(fill_values=False)
        self.assert_refused(p, "download of")
        self.assertEqual(self.log("node-exec"), [])


if __name__ == "__main__":
    unittest.main()
