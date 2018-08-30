#!/bin/sh

for profile in "$(dirname "$0")"/.profile.d/*.sh ; do
   . "$profile"
done

PATH="/app:$PATH"

mkdir /tmp/gnupg
chmod o-rwx /tmp/gnupg
cp /mnt/.gnupg/pubring.gpg /mnt/.gnupg/secring.gpg /mnt/.gnupg/trustdb.gpg \
   /gnupg

exec /bin/sh
