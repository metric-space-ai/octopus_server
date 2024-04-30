#!/usr/bin/env bash

NEXTCLOUD_SECRETS_FILE='/etc/davfs2/secrets'
grep -qF "$NEXTCLOUD_MOUNT_POINT $NEXTCLOUD_USERNAME $NEXTCLOUD_PASSWORD" "$NEXTCLOUD_SECRETS_FILE" || echo "$NEXTCLOUD_MOUNT_POINT $NEXTCLOUD_USERNAME $NEXTCLOUD_PASSWORD" >> "$NEXTCLOUD_SECRETS_FILE"
chmod 600 "$NEXTCLOUD_SECRETS_FILE"

echo "Attempting to mount the Nextcloud drive..."
mount -t davfs -o rw,uid=$(id -u),gid=$(id -g) "$NEXTCLOUD_URL" "$NEXTCLOUD_MOUNT_POINT"

if mountpoint -q "$NEXTCLOUD_MOUNT_POINT"; then
    echo "Nextcloud drive mounted successfully at $NEXTCLOUD_MOUNT_POINT"
else
    echo "Failed to mount Nextcloud drive."
fi
