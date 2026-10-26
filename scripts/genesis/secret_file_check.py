#!/usr/bin/env python3
"""secret_file_check.py: is a keystore password file private to the user running the ceremony?

Usage:
  secret_file_check.py <flag> <path>            check; print the file's identity on success
  secret_file_check.py <flag> <path> <identity>  check again; also require the same identity

<flag> is the option the path came from (e.g. --password-file); it is only used in messages.

The file must be a regular file (checked with lstat, so a symlink is refused, never
followed), owned by the effective user, with no group or world permission bits, and must sit
in a directory owned by that user or root that no one else can write (a sticky directory such
as /tmp is fine: others there cannot rename or remove the file). The identity is
"<dev>:<ino>:<ctime_ns>": a different file at the path, or any change to the file's mode or
content, changes it.

The file is never opened and its path is never printed: a caller that passed the password in
place of the path must not see it in a log. Exit 0 ok (identity on stdout), 1 refused (the
reason on stdout), 2 usage.
"""

import os
import stat
import sys


def refuse(flag: str, why: str) -> None:
    # On stdout, so a caller can capture the reason and log it under its own tag.
    print(f"{flag} {why}")
    sys.exit(1)


def check(flag: str, path: str) -> str:
    try:
        st = os.lstat(path)
    except OSError:
        refuse(flag, "must name an existing regular file (the path to the keystore password, not the password)")
    if stat.S_ISLNK(st.st_mode):
        refuse(flag, "must not be a symlink; pass the file itself")
    if not stat.S_ISREG(st.st_mode):
        refuse(flag, "must name an existing regular file (the path to the keystore password, not the password)")
    euid = os.geteuid()
    if st.st_uid != euid:
        refuse(flag, "must be owned by the user running the ceremony")
    if st.st_mode & 0o077:
        refuse(flag, "must not be readable or writable by group or others (create it under umask 077, or chmod 600 it)")
    if not st.st_mode & stat.S_IRUSR:
        refuse(flag, "must be readable by its owner (chmod 600 it)")
    parent = os.path.dirname(os.path.abspath(path)) or "/"
    try:
        dst = os.stat(parent)
    except OSError:
        refuse(flag, "must sit in a directory only its owner can change")
    if dst.st_uid not in (euid, 0):
        refuse(flag, "must sit in a directory only its owner can change (the directory belongs to another user)")
    if dst.st_mode & 0o022 and not dst.st_mode & stat.S_ISVTX:
        refuse(flag, "must sit in a directory only its owner can change (the directory is group- or world-writable)")
    return f"{st.st_dev}:{st.st_ino}:{st.st_ctime_ns}"


def main(argv: list) -> None:
    if len(argv) not in (3, 4):
        sys.stderr.write("usage: secret_file_check.py <flag> <path> [identity]\n")
        sys.exit(2)
    flag, path = argv[1], argv[2]
    ident = check(flag, path)
    if len(argv) == 4 and ident != argv[3]:
        refuse(flag, "changed since the preflight accepted it (another file at the path, or a new mode or content); stop and check the host")
    print(ident)


if __name__ == "__main__":
    main(sys.argv)
