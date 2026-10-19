#!/bin/sh
STATE_DIR=/run/droidvm-agent
FAILED_ACTIONS=
marker() { printf '\n__DROIDVM_AGENT__:%s\n' "$1"; }
command_log() { printf '\n[droidvm] $ %s\n' "$1"; }
release_mounts() {
    sync
    umount /mnt/proc >/dev/null 2>&1 || true
    umount /mnt/dev >/dev/null 2>&1 || true
    umount /mnt >/dev/null 2>&1 || true
    umount /mnt-autogrow >/dev/null 2>&1 || true
}
fail() {
    printf '%s\n' "$1" > "$STATE_DIR/error"
    exit 1
}
skip_action() {
    printf '%s\n' "$1" > "$STATE_DIR/skipped"
}
begin_action() {
    rm -f "$STATE_DIR/error" "$STATE_DIR/skipped"
    marker "ACTION:START:$ACTION_INDEX:$ACTION_TYPE"
}
end_action() {
    code=$(cat "$STATE_DIR/error" 2>/dev/null)
    [ -n "$code" ] || [ "$1" -eq 0 ] || code=SCRIPT_FAILED
    if [ -n "$code" ]; then
        release_mounts
        marker "ACTION:ERROR:$ACTION_INDEX:$ACTION_TYPE:$code"
        if [ "$ACTION_OPTIONAL" != true ]; then
            marker "RESULT:ERROR:$code"
            exit 0
        fi
        FAILED_ACTIONS="${FAILED_ACTIONS:+$FAILED_ACTIONS,}$ACTION_TYPE=$code"
        return 0
    fi
    if [ -s "$STATE_DIR/skipped" ]; then
        marker "ACTION:SKIPPED:$ACTION_INDEX:$ACTION_TYPE:$(cat "$STATE_DIR/skipped")"
    else
        marker "ACTION:OK:$ACTION_INDEX:$ACTION_TYPE"
    fi
}
mkdir -p /mnt /mnt-autogrow "$STATE_DIR"
