#!/bin/sh

for profile in "$(dirname "$0")"/.profile.d/*.sh ; do
   . "$profile"
done

exec /bin/sh
