# Native-only wrapper. The App's action bodies and rescue-shell mode are unchanged.
droidvm_prepare_finalizer() {
    DROIDVM_FINALIZE_STATUS=/run/droidvm-native-finalize-status
    DROIDVM_FINALIZE_RESULT=/run/droidvm-native-finalize-result
    : > "$DROIDVM_FINALIZE_STATUS" && : > "$DROIDVM_FINALIZE_RESULT"
}
droidvm_cleanup_failed() {
    if ! printf 'failed\n' >> "$DROIDVM_FINALIZE_STATUS"; then
        # A full initramfs must not turn a failed sticky write into success.
        # Absence is also a failure in droidvm_finalize.
        rm -f "$DROIDVM_FINALIZE_STATUS"
        return 1
    fi
}
droidvm_checked() {
    command "$@"
    droidvm_command_status=$?
    if [ "$droidvm_command_status" -ne 0 ]; then
        droidvm_cleanup_failed || return 1
    fi
    return "$droidvm_command_status"
}
# The action bodies contain unchecked sync calls and best-effort unmounts.
# A file on the rescue initramfs preserves failures across their subshells.
sync() { droidvm_checked sync "$@"; }
umount() { droidvm_checked umount "$@"; }
droidvm_marker() {
    case "$1" in
        RESULT:*) printf 'result\n' > "$DROIDVM_FINALIZE_RESULT" || droidvm_cleanup_failed ;;
    esac
    printf '\n__DROIDVM_AGENT__:%s\n' "$1"
}
droidvm_mount_present() {
    droidvm_mount_table=$(cat /proc/mounts 2>/dev/null) || return 2
    printf '%s\n' "$droidvm_mount_table" |
        awk -v target="$1" '$2 == target { found=1 } END { exit !found }'
}
droidvm_mounts_clear() {
    droidvm_mount_table=$(cat /proc/mounts 2>/dev/null) || return 1
    # Include unexpected child mounts and stacked mounts left after unmount.
    printf '%s\n' "$droidvm_mount_table" |
        awk '$2 == "/mnt" || index($2, "/mnt/") == 1 ||
             $2 == "/mnt-autogrow" || index($2, "/mnt-autogrow/") == 1 { found=1 }
             END { exit found ? 1 : 0 }'
}
droidvm_finalize() {
    droidvm_cleanup_ok=true
    sync >/dev/null 2>&1 || droidvm_cleanup_ok=false
    for droidvm_mount in /mnt/proc /mnt/dev /mnt /mnt-autogrow; do
        if droidvm_mount_present "$droidvm_mount"; then
            umount "$droidvm_mount" >/dev/null 2>&1 || droidvm_cleanup_ok=false
        else
            # An absent mount is fine; a failed mount-table read is not.
            [ "$?" -eq 1 ] || droidvm_cleanup_ok=false
        fi
    done
    droidvm_mounts_clear || droidvm_cleanup_ok=false
    if [ ! -f "$DROIDVM_FINALIZE_STATUS" ] || [ -s "$DROIDVM_FINALIZE_STATUS" ]; then
        droidvm_cleanup_ok=false
    fi
    if [ "$droidvm_cleanup_ok" = true ]; then
        printf '\n__DROIDVM_AGENT__:CLEANUP:OK\n'
        return 0
    fi
    printf '\n__DROIDVM_AGENT__:CLEANUP:ERROR\n'
    return 1
}
droidvm_run() {
    if ! droidvm_prepare_finalizer; then
        printf '\n__DROIDVM_AGENT__:RESULT:ERROR:SCRIPT_FAILED\n'
        printf '\n__DROIDVM_AGENT__:CLEANUP:ERROR\n'
        return 0
    fi
    # A foreground passwd and every action subshell must finish before cleanup.
    # In particular, end_action's required-failure exit cannot skip finalization.
    ( droidvm_actions )
    droidvm_action_status=$?
    if [ ! -s "$DROIDVM_FINALIZE_RESULT" ]; then
        droidvm_marker RESULT:ERROR:SCRIPT_FAILED
    fi
    if [ "$droidvm_action_status" -ne 0 ]; then
        droidvm_cleanup_failed || true
    fi
    droidvm_finalize || true
    # The terminal marker carries the result. Do not cause the serial bootstrap
    # command to append a second RESULT:ERROR after finalization.
    return 0
}
