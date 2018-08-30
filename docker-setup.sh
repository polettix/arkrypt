#!/bin/sh
set -e

for profile in "$(dirname "$0")"/.profile.d/*.sh ; do
   . "$profile"
done

PATH="/app:$PATH"

export GNUPGHOME=/tmp/gnupg
mkdir "$GNUPGHOME"
chmod og-rwx "$GNUPGHOME"

if [ -f '/mnt/.gnupg' ] ; then
   tar xC "$GNUPGHOME" -f /mnt/.gnupg
elif [ -d '/mnt/.gnupg' ] ; then
   for f in pubring.gpg secring.gpg trustdb.gpg .gpg-v21-migrated ; do
      path="/mnt/.gnupg/$f"
      [ -e "$path" ] || continue
      cp "$path" "$GNUPGHOME"
   done
   if [ -d "/mnt/.gnupg/private-keys-v1.d" ] ; then
      mkdir -p "$GNUPGHOME/private-keys-v1.d"
      cp /mnt/.gnupg/private-keys-v1.d/* "$GNUPGHOME/private-keys-v1.d"
   fi
elif [ -e '/mnt/.gnupg-export' ] ; then
   source='/mnt/.gnupg-export'
   if [ -f "$source" ] ; then
      file="$source"
      source="$GNUPGHOME/exports"
      mkdir -p "$source"
      tar xC "$source" -f "$file"
   fi
   for f in secret public ; do
      [ -e "$source/$f" ] && gpg --import < "$source/$f"
   done
   [ -e "$source/ownertrust" ] \
      && gpg --import-ownertrust < "$source/ownertrust"
else
   printf >&2 '%s\n' 'cannot set gnupg up properly'
fi

export GPG_TTY='/dev/console'

exec /bin/sh
