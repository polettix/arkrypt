#!/bin/sh
set -e

for profile in "$(dirname "$0")"/.profile.d/*.sh ; do
   . "$profile"
done

PATH="/app:$PATH"

export GNUPGHOME=/tmp/gnupg
mkdir "$GNUPGHOME"
chmod og-rwx "$GNUPGHOME"

gnupg_src='/mnt/.gnupg'
if [ -f "$gnupg_src" ] ; then
   src="$gnupg_src"
   gnupg_src="$GNUPGHOME/extract"
   mkdir -p "$gnupg_src"
   tar xC "$gnupg_src" -f "$src"
fi

if [ -e "$gnupg_src/pubring.gpg" ] ; then
   for f in pubring.gpg secring.gpg trustdb.gpg .gpg-v21-migrated ; do
      path="$gnupg_src/$f"
      [ -e "$path" ] || continue
      cp "$path" "$GNUPGHOME"
   done
   if [ -d "/mnt/.gnupg/private-keys-v1.d" ] ; then
      mkdir -p "$GNUPGHOME/private-keys-v1.d"
      cp "$gnupg_src/private-keys-v1.d"/* "$GNUPGHOME/private-keys-v1.d"
   fi
elif [ -e "$gnupg_src/public" ] ; then
   for f in secret public ; do
      [ -e "$gnupg_src/$f" ] && gpg --import < "$gnupg_src/$f"
   done
   [ -e "$gnupg_src/ownertrust" ] \
      && gpg --import-ownertrust < "$gnupg_src/ownertrust"
else
   printf >&2 '%s\n' 'cannot set gnupg up properly'
fi

export GPG_TTY='/dev/console'

exec /bin/sh
