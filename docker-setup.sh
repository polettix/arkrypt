#!/bin/sh

for profile in "$(dirname "$0")"/.profile.d/*.sh ; do
   . "$profile"
done

PATH="/app:$PATH"

export GNUPGHOME=/tmp/gnupg
mkdir "$GNUPGHOME"
chmod og-rwx "$GNUPGHOME"
cp /mnt/.gnupg/pubring.gpg /mnt/.gnupg/secring.gpg /mnt/.gnupg/trustdb.gpg \
   "$GNUPGHOME"

exec /bin/sh
