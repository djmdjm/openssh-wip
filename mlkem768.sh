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
#git fetch
git checkout -B extract 1>&2
git reset --hard $WANT_LIBCRUX_REVISION 1>&2
LIBCRUX_REVISION=`git rev-parse HEAD`
set +x

cd $START
(
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
	# Remove incorrect license text, with permission:
	# Message-ID: <CAACePAKad5bFex4T0U6w2C4poXpng-UqfaCtU0eo4OthyQuE0w@mail.gmail.com>
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

echo
echo '/* rename some types to be a bit more ergonomic */'
echo '#define libcrux_mlkem_keypair libcrux_ml_kem_mlkem768_MlKem768KeyPair_s'
echo '#define libcrux_mlkem_pk_valid_result Option_92_s'
echo '#define libcrux_mlkem_pk libcrux_ml_kem_types_MlKemPublicKey_15_s'
echo '#define libcrux_mlkem_sk libcrux_ml_kem_types_MlKemPrivateKey_55_s'
echo '#define libcrux_mlkem_ciphertext libcrux_ml_kem_mlkem768_MlKem768Ciphertext_s'
echo '#define libcrux_mlkem_enc_result tuple_3c_s'
) > libcrux_mlkem768_sha3.h_new

# Do some checks on the resultant file

crypto_api_val() {
	grep "^#define $1 " crypto_api.h | sed "s/.*$1 //" | sed 's/ //g'
}

PUBLICKEYBYTES=`crypto_api_val crypto_kem_mlkem768_PUBLICKEYBYTES`
SECRETKEYBYTES=`crypto_api_val crypto_kem_mlkem768_SECRETKEYBYTES`
CIPHERTEXTBYTES=`crypto_api_val crypto_kem_mlkem768_CIPHERTEXTBYTES`
BYTES=`crypto_api_val crypto_kem_mlkem768_BYTES`

echo "Checking: " 1>&2
echo "    crypto_kem_mlkem768_PUBLICKEYBYTES == $PUBLICKEYBYTES" 1>&2
echo "    crypto_kem_mlkem768_SECRETKEYBYTES == $SECRETKEYBYTES" 1>&2
echo "    crypto_kem_mlkem768_CIPHERTEXTBYTES == $CIPHERTEXTBYTES" 1>&2
echo "    crypto_kem_mlkem768_BYTES == $BYTES" 1>&2

sed -e '/^typedef struct libcrux_ml_kem_types_MlKemPublicKey_15_s {$/,/^} libcrux_ml_kem_types_MlKemPublicKey_15;$/!d' \
	< libcrux_mlkem768_sha3.h_new \
	| grep -q "uint8_t value\[${PUBLICKEYBYTES}U\];" \
	|| die "crypto_kem_mlkem768_PUBLICKEYBYTES mismatch"
sed -e '/^typedef struct libcrux_ml_kem_types_MlKemPrivateKey_55_s {$/,/^} libcrux_ml_kem_types_MlKemPrivateKey_55;$/!d' \
	< libcrux_mlkem768_sha3.h_new \
	| grep -q "uint8_t value\[${SECRETKEYBYTES}U\];" \
	|| die "crypto_kem_mlkem768_SECRETKEYBYTES mismatch"
sed -e '/^typedef struct libcrux_ml_kem_mlkem768_MlKem768Ciphertext_s {$/,/^} libcrux_ml_kem_mlkem768_MlKem768Ciphertext;$/!d' \
	< libcrux_mlkem768_sha3.h_new \
	| grep -q "uint8_t value\[${CIPHERTEXTBYTES}U\];" \
	|| die "crypto_kem_mlkem768_CIPHERTEXTBYTES mismatch"
sed -e '/^typedef struct tuple_3c_s {$/,/^} tuple_3c;$/!d' \
	< libcrux_mlkem768_sha3.h_new \
	| grep -q "uint8_t snd\[${BYTES}U\];" \
	|| die "crypto_kem_mlkem768_BYTES mismatch in libcrux_ml_kem_mlkem768_portable_kyber_encapsulate result"
sed -e '/^static inline void libcrux_ml_kem_mlkem768_portable_kyber_decapsulate[(]$/,/[)] {$/!d' \
	< libcrux_mlkem768_sha3.h_new \
	| grep -q ", uint8_t ret\[${BYTES}U\]" \
	|| die "crypto_kem_mlkem768_BYTES mismatch in libcrux_ml_kem_mlkem768_portable_kyber_decapsulate"

# Extract PRNG inputs; there's no nice #defines for these
key_pair_rng_len=`sed -e '/^libcrux_ml_kem_mlkem768_portable_kyber_generate_key_pair[(]$/,/[)] {$/!d' < libcrux_mlkem768_sha3.h_new | grep 'uint8_t randomness\[[0-9]*U\][)]' | sed 's/.*randomness\[\([0-9]*\)U\].*/\1/'`
enc_rng_len=`sed -e '/^static inline tuple_3c libcrux_ml_kem_mlkem768_portable_kyber_encapsulate[(]$/,/[)] {$/!d' < libcrux_mlkem768_sha3.h_new | grep 'uint8_t randomness\[[0-9]*U\][)]' | sed 's/.*randomness\[\([0-9]*\)U\].*/\1/'`
test -z "$key_pair_rng_len" && die "couldn't find size of libcrux_ml_kem_mlkem768_portable_kyber_generate_key_pair randomness argument"
test -z "$enc_rng_len" && die "couldn't find size of libcrux_ml_kem_mlkem768_portable_kyber_encapsulate randomness argument"

(
echo "/* defines for PRNG inputs */"
echo "#define LIBCRUX_ML_KEM_KEY_PAIR_PRNG_LEN $key_pair_rng_len"
echo "#define LIBCRUX_ML_KEM_ENC_PRNG_LEN $enc_rng_len"
) >> libcrux_mlkem768_sha3.h_new

echo "Found:" 1>&2
echo "    LIBCRUX_ML_KEM_KEY_PAIR_PRNG_LEN = $key_pair_rng_len" 1>&2
echo "    LIBCRUX_ML_KEM_ENC_PRNG_LEN = $enc_rng_len" 1>&2

mv libcrux_mlkem768_sha3.h_new libcrux_mlkem768_sha3.h
echo 1>&2
echo "libcrux_mlkem768_sha3.h OK" 1>&2

