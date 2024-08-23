#!/bin/sh
#       $OpenBSD$
#       Placed in the Public Domain.
#

WANT_LIBCRUX_REVISION="origin/main"

FILES="
	libcrux/libcrux-ml-kem/cg/eurydice_glue.h
	libcrux/libcrux-ml-kem/cg/libcrux_core.h
	libcrux/libcrux-ml-kem/cg/libcrux_ct_ops.h
	libcrux/libcrux-ml-kem/cg/libcrux_sha3_portable.h
	libcrux/libcrux-ml-kem/cg/libcrux_mlkem768_portable.h
"

START="$PWD"
die() {
	echo "$@" 1>&2
	exit 1
}

set -xe
test -d libcrux || git clone https://github.com/cryspen/libcrux
cd libcrux
test `git diff | wc -l` -ne 0 && die "tree has unstaged changes"
git fetch
git checkout -B extract 1>&2
git reset --hard $WANT_LIBCRUX_REVISION 1>&2
LIBCRUX_REVISION=`git rev-parse HEAD`

set -e
cd $START
echo -n '/*  $OpenBSD$ */'
echo
echo "/* Extracted from libcrux revision $LIBCRUX_REVISION */"
echo
echo '/*'
cat libcrux/LICENSE-MIT | sed 's/^/ * /;s/ *$//'
echo ' */'
echo
echo '#if !defined(__GNUC__) || (__GNUC__ < 2)'
echo '# define __attribute__(x)'
echo '#endif'
echo '#define KRML_MUSTINLINE inline'
echo '#define KRML_NOINLINE __attribute__((noinline, unused))'
echo '#define KRML_HOST_EPRINTF(...)'
echo '#define KRML_HOST_EXIT(x) fatal_f("internal error")'
echo
for i in $FILES; do
	echo "/* from $i */"
	# Changes to all files:
	#  - remove all includes, we inline everything required.
	#  - make functions not required elsewhere static.
	#  - rename the functions we do use.
	#  - remove unnecessary defines and externs.
	sed -e "/#include/d" \
	    -e 's/[	 ]*$//' \
	    $i | \
	case "$i" in
	# Remove incorrect license text.
	libcrux/libcrux-ml-kem/cg/eurydice_glue.h)
	    sed \
		-e '/^[/][*]/,/^ [*][/]$/d' \
	    ;;
	# Default: pass through.
	*)
	    cat
	    ;;
	esac
	echo
done
