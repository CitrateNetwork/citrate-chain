#!/usr/bin/env bash
# Fixture (signal-synthetic-pid, positive): a shell test signalling a hard-coded pid.
kill -9 4242 # FLAG
kill -TERM -- -1 # FLAG
