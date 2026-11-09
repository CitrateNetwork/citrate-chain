#!/usr/bin/env bash
# Fixture (signal-synthetic-pid, negative): liveness probes and spawned pids only.
sleep 30 & pid=$!
kill -0 "$pid"
kill -0 4242 2>/dev/null || echo "gone"
kill -9 "$pid"
