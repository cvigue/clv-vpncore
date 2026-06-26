#!/bin/bash

list_perf_profiles() {
    cat <<'EOF'
Profiles:
  clean           No underlay impairment
  lat20           20ms one-way delay on both bridge-facing links
  lat100          100ms one-way delay on both bridge-facing links
  lat100_loss1    100ms one-way delay plus 1% packet loss on both bridge-facing links
EOF
}

perf_profile_exists() {
    case "$1" in
        clean|lat20|lat100|lat100_loss1) return 0 ;;
        *) return 1 ;;
    esac
}

perf_profile_label() {
    case "$1" in
        clean) echo "Clean baseline" ;;
        lat20) echo "20ms latency" ;;
        lat100) echo "100ms latency" ;;
        lat100_loss1) echo "100ms latency + 1% loss" ;;
        *) return 1 ;;
    esac
}

perf_profile_requires_netem() {
    [[ "$1" != "clean" ]]
}

perf_profile_args() {
    case "$1" in
        clean) echo "" ;;
        lat20) echo "delay 20ms" ;;
        lat100) echo "delay 100ms" ;;
        lat100_loss1) echo "delay 100ms loss 1%" ;;
        *) return 1 ;;
    esac
}
