FILESYSTEMS=$(blkid)
echo "$FILESYSTEMS" | grep -q 'TYPE="btrfs"' && modprobe btrfs >/dev/null 2>&1 || true
echo "$FILESYSTEMS" | grep -q 'TYPE="xfs"' && modprobe xfs >/dev/null 2>&1 || true
echo "$FILESYSTEMS" | grep -q 'TYPE="f2fs"' && modprobe f2fs >/dev/null 2>&1 || true
TARGET_DEVICE=""
for dev in $(echo "$FILESYSTEMS" | grep -E 'TYPE="(ext2|ext3|ext4|btrfs|xfs|f2fs)"' | cut -d: -f1); do
    marker "PROBE:$dev"
    if mount -o rw "$dev" /mnt >/dev/null 2>&1; then
        if [ -f /mnt/etc/passwd ]; then
            TARGET_DEVICE="$dev"
            break
        fi
        umount /mnt >/dev/null 2>&1 || true
    fi
done
[ -n "$TARGET_DEVICE" ] || fail ROOT_NOT_FOUND
printf '%s\n' "$TARGET_DEVICE" > /run/droidvm-root-device
marker "ROOT:$TARGET_DEVICE"
[ -d /mnt/dev ] || fail PASSWD_FAILED
[ -d /mnt/proc ] || fail PASSWD_FAILED
mount -o bind /dev /mnt/dev || fail PASSWD_FAILED
mount -t proc proc /mnt/proc || fail PASSWD_FAILED
PASSWD_BIN=
for candidate in /usr/bin/passwd /bin/passwd /usr/sbin/passwd /sbin/passwd; do
    [ -x "/mnt$candidate" ] || continue
    PASSWD_BIN=$candidate
    break
done
if [ -z "$PASSWD_BIN" ]; then
    for candidate in /bin/busybox /usr/bin/busybox; do
        [ -x "/mnt$candidate" ] || continue
        PASSWD_BIN="$candidate passwd"
        break
    done
fi
[ -n "$PASSWD_BIN" ] || fail PASSWD_NOT_FOUND
marker "PASSWD:BINARY:$PASSWD_BIN"
change_password() {
    marker "PASSWD:$1"
    command_log "LC_ALL=C busybox chroot /mnt $PASSWD_BIN $1"
    LC_ALL=C busybox chroot /mnt $PASSWD_BIN "$1"
    rc=$?
    marker "COMMAND:RC:PASSWD:$1:$rc"
    [ "$rc" -eq 0 ] || fail PASSWD_FAILED
}
change_password root
if [ "$CHANGE_NORMAL_USERS" = true ]; then
    for user in $(awk -F: '$3 >= 1000 && $3 < 2000 {print $1}' /mnt/etc/passwd); do
        change_password "$user"
    done
fi
sync
umount /mnt/proc >/dev/null 2>&1 || fail UNMOUNT_FAILED
umount /mnt/dev >/dev/null 2>&1 || fail UNMOUNT_FAILED
umount /mnt >/dev/null 2>&1 || fail UNMOUNT_FAILED
