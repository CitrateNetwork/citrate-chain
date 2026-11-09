#!/usr/bin/env bash
# Fixture (signal-synthetic-pid, negative): runs in a private pid namespace, so a literal pid
# can only name a process inside it.
exec unshare --user --map-root-user --pid --fork --mount-proc bash -c 'sleep 30 & kill -9 2'
