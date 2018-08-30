#!/bin/sh

for profile in "$(dirname "$0")"/.profile.d/*.sh ; do
   . "$profile"
done

PATH="/app:$PATH"
exec /bin/sh
