#!/bin/bash

set -eo pipefail
[ -r "$HOME/.arkryptrc" ] && . "$HOME/.arkryptrc"

main () {
   local command keyid command_args
   parse_options "$@"

   case "$command" in
      (d|dec|decrypt)
         run_decrypt "$file"
         ;;
      (e|enc|encrypt)
         run_encrypt "$file"
         ;;
      (f|filename)
         run_filename "$file"
         ;;
      (l|list)
         run_list
         ;;
      (regenlist)
         run_regenlist "$file"
         ;;
      (squashlist)
         run_squashlist
         ;;
      (*)
         die "unknown command $command"
         ;;
   esac
}

die() {
   printf '%s\n' "$*" >&2
   exit 1
}

parse_options() {
   command="$1"
   file="$2"
   keyid="${ARKRYPT_KEYID:-"pass@polettix.it"}" # FIXME
}

encrypt_stdin_ascii() {
   gpg -a -r "$keyid" -o "$1" --trust-model always -e
}

encrypt_file_binary() {
   gpg -r "$keyid" -o "$2.tmp" --trust-model always -e "$1"
   mv "$2.tmp" "$2"
}

add_to_list() {
   local digest="$1" file="$2"
   {
      [ -e 'akt.list' ] && cat akt.list
      printf '%s %s\n' "$digest" "$file" | encrypt_stdin_ascii -
   } > atk.list.tmp
   mv akt.list.tmp akt.list
}

run_encrypt() {
   local file="$1"
   [ -r "$file" ] || die "cannot read $file"
   local digest="akt-$(md5sum "$file" | sed -e 's/^.*= *//;s/ .*//')"
   [ -e "$digest.data" ] && die "target $digest.data already exists"

   printf '%s\n' "$file" | encrypt_stdin_ascii "$digest.name"
   encrypt_file_binary "$file" "$digest.data"

   add_to_list "$digest" "$file"
}

get_filename() {
   local digest="${1%%.*}"
   [ -e "$digest.data" ] || die "file $digest.data does not exist"
   [ -e "$digest.name" ] || die "file $digest.name does not exist"
   gpg --output - --quiet --decrypt "$digest.name"
}

run_filename() {
   local filename="$(get_filename "$1")"
   printf '%s\n' "$filename"
}

run_decrypt() {
   local digest="${1%%.*}"
   local filename="${2:-"$(get_filename "$digest")"}"
   [ -e "$filename" ] && die "target file $filename exists"
   gpg --output "$filename" --quiet --decrypt "$digest.data"
   printf '%s\n' "$filename"
}

run_list() {
   [ -e 'akt.list' ] || die 'no file listing akt.list present'
   gpg --output - --quiet --allow-multiple-messages --decrypt akt.list \
      2>/dev/null
}

run_regenlist() {
   local check="$1"
   local file name digest
   rm -f akt.list.tmp
   for file in akt-*.name ; do
      digest="${file%%.*}"
      if [ "$check" = "names" ] ; then
         name="$(gpg --output - --quiet --decrypt "$file")"
      else
         name="$(get_filename "$digest")"
      fi
      printf '%s %s\n' "$digest" "$name"
   done | encrypt_stdin_ascii akt.list.tmp
   mv akt.list.tmp akt.list
}

run_squashlist() {
   rm -f akt.list.tmp
   run_list | encrypt_stdin_ascii akt.list.tmp
   mv akt.list.tmp akt.list
}

main "$@"