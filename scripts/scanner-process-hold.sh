#!/usr/bin/env bash

# These functions are sourced by verify-scanner-sandbox.sh so the PID and
# starttime remain in the caller shell for descriptor checks and EXIT cleanup.
# The caller provides scanner_pid, scanner_process_starttime,
# scanner_process_state, expect_scanner_starttime, docker, and fail.
held_scanner_pid=
held_scanner_starttime=

# Stop exactly one live scanner before reading its mutable /proc state. Keep
# its PID and starttime so cleanup can never resume a recycled process ID.
hold_scanner_process() {
  local name=$1 required_arg=$2 pid starttime state
  [ -z "$held_scanner_pid" ] || fail "scanner PID $held_scanner_pid is still held while selecting another scanner"
  pid=$(scanner_pid "$name" "$required_arg")
  [ -n "$pid" ] || fail "no live $name scan with argument $required_arg appeared"
  starttime=$(scanner_process_starttime "$pid") || fail "$name PID $pid has no readable starttime before it was held"
  held_scanner_pid=$pid
  held_scanner_starttime=$starttime
  expect_scanner_starttime "$pid" "$starttime" "immediately before SIGSTOP"
  docker exec "$container" kill -STOP "$pid" || fail "could not stop the selected $name process $pid"
  for attempt in $(seq 1 40); do
    state=$(scanner_process_state "$pid" || true)
    if [ "$state" = T ] || [ "$state" = t ]; then
      expect_scanner_starttime "$pid" "$starttime" "after it was stopped for inspection"
      return
    fi
    sleep 0.1
  done
  fail "$name PID $pid did not enter a stopped state for inspection (state '$state')"
}

resume_held_scanner() {
  local pid=${held_scanner_pid:-} starttime=${held_scanner_starttime:-} current
  [ -n "$pid" ] || return 0
  if current=$(scanner_process_starttime "$pid" 2>/dev/null) && [ "$current" = "$starttime" ]; then
    docker exec "$container" kill -CONT "$pid" || fail "could not resume held scanner process $pid"
    for attempt in $(seq 1 40); do
      current=$(scanner_process_state "$pid" || true)
      if [ "$current" != T ] && [ "$current" != t ]; then
        held_scanner_pid=
        held_scanner_starttime=
        return 0
      fi
      sleep 0.1
    done
    fail "held scanner process $pid remained stopped after SIGCONT"
  fi
  # The selected process already exited or its PID was recycled. Never signal
  # a PID whose starttime no longer matches the recorded process.
  held_scanner_pid=
  held_scanner_starttime=
}
