#!/bin/sh
# Runs on Git for Windows sh or Linux sh. Every sync/umount and /proc/mounts
# access is replaced; this contract never mounts or unmounts the host.
set -u
die() { printf '%s\n' "finalizer contract: $*" >&2; exit 1; }
test_base=$(CDPATH= cd -- "${TMPDIR:-/tmp}" && pwd -P) || exit 1
test_root=$(mktemp -d "$test_base/droidvm-agent-finalizer.XXXXXX") || exit 1
cleanup_fixture() {
    case "$test_root" in
        "$test_base"/droidvm-agent-finalizer.*) rm -rf -- "$test_root" ;;
        *) printf 'Refused cleanup outside finalizer temporary directory\n' >&2 ;;
    esac
}
trap cleanup_fixture EXIT HUP INT TERM
test_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
. "${1:-$test_script_dir/../agent/scripts/droidvm-agent/finalize.sh}"
mkdir "$test_root/bin" || die 'fixture setup'
export DROIDVM_FINALIZER_TEST_DIR="$test_root"
cat > "$test_root/bin/sync" <<'MOCK'
#!/bin/sh
printf 'sync\n' >> "$DROIDVM_FINALIZER_TEST_DIR/calls"
if [ -f "$DROIDVM_FINALIZER_TEST_DIR/sync-fail-once" ]; then
    rm "$DROIDVM_FINALIZER_TEST_DIR/sync-fail-once"
    exit 1
fi
exit 0
MOCK
cat > "$test_root/bin/umount" <<'MOCK'
#!/bin/sh
printf 'umount %s\n' "$1" >> "$DROIDVM_FINALIZER_TEST_DIR/calls"
[ ! -f "$DROIDVM_FINALIZER_TEST_DIR/unmount-fail" ] || exit 1
[ ! -f "$DROIDVM_FINALIZER_TEST_DIR/mount-remains" ] || exit 0
awk -v target="$1" '$2 != target' "$DROIDVM_FINALIZER_TEST_DIR/mounts" > "$DROIDVM_FINALIZER_TEST_DIR/mounts-next" || exit 1
mv "$DROIDVM_FINALIZER_TEST_DIR/mounts-next" "$DROIDVM_FINALIZER_TEST_DIR/mounts"
MOCK
chmod +x "$test_root/bin/sync" "$test_root/bin/umount" || die 'mock executable setup'
PATH="$test_root/bin:$PATH"
export PATH
cat() {
    if [ "$#" -eq 1 ] && [ "$1" = /proc/mounts ]; then
        [ ! -f "$test_root/mount-read-fail" ] || return 1
        command cat "$test_root/mounts"
    else
        command cat "$@"
    fi
}
# Override only the fixed /run storage initializer. All production wrapper,
# command recording, mount checks and cleanup logic execute unchanged.
droidvm_prepare_finalizer() {
    DROIDVM_FINALIZE_STATUS="$test_root/status"
    DROIDVM_FINALIZE_RESULT="$test_root/result"
    : > "$DROIDVM_FINALIZE_STATUS" && : > "$DROIDVM_FINALIZE_RESULT"
}
reset_fixture() {
    rm -f "$test_root/sync-fail-once" "$test_root/unmount-fail" "$test_root/mount-remains" "$test_root/mount-read-fail"
    : > "$test_root/calls"
    : > "$test_root/mounts"
}
expect_marker() {
    test_count=$(grep -Fxc "__DROIDVM_AGENT__:$1" "$test_root/output" || true)
    [ "$test_count" -eq 1 ] || die "expected one $1"
}
expect_cleanup() {
    expect_marker "CLEANUP:$1"
    test_count=$(grep -c '^__DROIDVM_AGENT__:CLEANUP:' "$test_root/output" || true)
    [ "$test_count" -eq 1 ] || die 'duplicate cleanup marker'
}
run_fixture() {
    droidvm_run > "$test_root/output" 2> "$test_root/error" || die 'wrapper must not append another bootstrap RESULT'
}

reset_fixture
printf 'proc /mnt/proc proc rw 0 0\ndev /mnt/dev none rw 0 0\ndisk /mnt ext4 rw 0 0\ndisk2 /mnt-autogrow btrfs rw 0 0\n' > "$test_root/mounts"
droidvm_actions() { droidvm_marker RESULT:OK; }
run_fixture
expect_marker RESULT:OK
expect_cleanup OK
test_calls=$(command cat "$test_root/calls")
[ "$test_calls" = 'sync
umount /mnt/proc
umount /mnt/dev
umount /mnt
umount /mnt-autogrow' ] || die 'cleanup ordering'
[ ! -s "$test_root/mounts" ] || die 'all target mounts removed'

# Required failures exit the inner shell but cannot skip the outer finalizer.
reset_fixture
droidvm_actions() { droidvm_marker RESULT:ERROR:PASSWD_FAILED; exit 0; }
run_fixture
expect_marker RESULT:ERROR:PASSWD_FAILED
expect_cleanup OK

reset_fixture
droidvm_actions() { exit 7; }
run_fixture
expect_marker RESULT:ERROR:SCRIPT_FAILED
expect_cleanup ERROR

# A late abnormal exit must not duplicate an already-published RESULT.
reset_fixture
droidvm_actions() { droidvm_marker RESULT:OK; exit 9; }
run_fixture
expect_marker RESULT:OK
expect_cleanup ERROR
test_count=$(grep -c '^__DROIDVM_AGENT__:RESULT:' "$test_root/output" || true)
[ "$test_count" -eq 1 ] || die 'duplicate result after abnormal exit'

# An ignored sync failure in an action subshell stays latched even when the
# final sync succeeds. This is the original App bodies' unchecked-sync case.
reset_fixture
: > "$test_root/sync-fail-once"
droidvm_actions() { ( sync ); droidvm_marker RESULT:OK; }
run_fixture
expect_marker RESULT:OK
expect_cleanup ERROR

reset_fixture
: > "$test_root/sync-fail-once"
droidvm_actions() { droidvm_marker RESULT:OK; }
run_fixture
expect_cleanup ERROR

reset_fixture
printf 'disk /mnt ext4 rw 0 0\n' > "$test_root/mounts"
: > "$test_root/unmount-fail"
run_fixture
expect_cleanup ERROR

reset_fixture
printf 'disk /mnt ext4 rw 0 0\n' > "$test_root/mounts"
: > "$test_root/mount-remains"
run_fixture
expect_cleanup ERROR

reset_fixture
printf 'dev /mnt/dev/pts devpts rw 0 0\n' > "$test_root/mounts"
run_fixture
expect_cleanup ERROR

reset_fixture
: > "$test_root/mount-read-fail"
run_fixture
expect_cleanup ERROR

reset_fixture
droidvm_prepare_finalizer() { return 1; }
droidvm_actions() { printf 'unexpected action\n' > "$test_root/actions-ran"; }
run_fixture
expect_marker RESULT:ERROR:SCRIPT_FAILED
expect_cleanup ERROR
[ ! -e "$test_root/actions-ran" ] || die 'failed initialization executed actions'
[ ! -s "$test_root/calls" ] || die 'failed initialization invoked cleanup commands'
printf 'Native finalizer wrapper, sticky failures and verified unmount contracts passed\n'
