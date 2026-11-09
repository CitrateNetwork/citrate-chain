# Fixture (installer-test-sandbox, positive): a Python test that runs a release script with the
# inherited environment. The marked line must be flagged.
import subprocess


def test_release_refuses_unsigned(tmp_path):
    r = subprocess.run(["bash", "scripts/release/publish.sh", "--dry-run"], capture_output=True)  # FLAG
    assert r.returncode != 0
