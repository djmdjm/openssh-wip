This describes the key/certificate revocation list format for OpenSSH.

1. Overall format

The KRL consists of a header and zero or more sections. The header is:

#define KRL_MAGIC		0x5353484b524c0a00ULL  /* "SSHKRL\n\0" */
#define KRL_FORMAT_VERSION	1

	uint64	KRL_MAGIC
	uint32	KRL_FORMAT_VERSION
	uint64	krl_version
	uint64	generated_date
	uint64	flags
	string	reserved
	string	comment

Where "krl_version" is a version number that increases each time the KRL
is modified, "generated_date" is the time in seconds since 1970-01-01
00:00:00 UTC that the KRL was generated, "comment" is an optional comment
and "reserved" an extension field whose contents are currently ignored.
No "flags" are currently defined.

Following the header are zero or more sections, each consisting of:

	byte	section_type
	string	section_data

Where "section_type" indicates the type of the "section_data". An exception
to this is the KRL_SECTION_SIGNATURE section, that has a slightly different
format (see below).

The available section types are:

#define KRL_SECTION_CERTIFICATES		1
#define KRL_SECTION_EXPLICIT_KEY		2
#define KRL_SECTION_FINGERPRINT_SHA1		3
#define KRL_SECTION_SIGNATURE			4
#define KRL_SECTION_FINGERPRINT_SHA256		5
#define KRL_SECTION_EXTENSION			255

2. Certificate section

These sections use type KRL_SECTION_CERTIFICATES to revoke certificates by
serial number or key ID. The consist of the CA key that issued the
certificates to be revoked and a reserved field whose contents is currently
ignored.

	string ca_key
	string reserved

Where "ca_key" is the standard SSH wire serialisation of the CA's
public key. Alternately, "ca_key" may be an empty string to indicate
the certificate section applies to all CAs (this is most useful when
revoking key IDs).

Followed by one or more sections:

	byte	cert_section_type
	string	cert_section_data

The certificate section types are:

#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_KEY_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

2.1 Certificate serial list section

This section is identified as KRL_SECTION_CERT_SERIAL_LIST. It revokes
certificates by listing their serial numbers. The cert_section_data in this
case contains:

	uint64	revoked_cert_serial
	uint64	...

This section may appear multiple times.

2.2. Certificate serial range section

These sections use type KRL_SECTION_CERT_SERIAL_RANGE and hold
a range of serial numbers of certificates:

	uint64	serial_min
	uint64	serial_max

All certificates in the range serial_min <= serial <= serial_max are
revoked.

This section may appear multiple times.

2.3. Certificate serial bitmap section

Bitmap sections use type KRL_SECTION_CERT_SERIAL_BITMAP and revoke keys
by listing their serial number in a bitmap.

	uint64	serial_offset
	mpint	revoked_keys_bitmap

A bit set at index N in the bitmap corresponds to revocation of a keys with
serial number (serial_offset + N).

This section may appear multiple times.

2.4. Revoked key ID sections

KRL_SECTION_CERT_KEY_ID sections revoke particular certificate "key
ID" strings. This may be useful in revoking all certificates
associated with a particular identity, e.g. a host or a user.

	string	key_id[0]
	...

This section must contain at least one "key_id". This section may appear
multiple times.

2.5. Certificate Extension subsections

This subsection type provides a generic extension mechanism to the
certificates KRL section that may be used to provide optional or critical
data.

Extensions are stored in subsections of type
KRL_SECTION_CERT_EXTENSION with the following contents:

	string	extension_name
	boolean is_critical
	string	extension_contents.

Where "extension_name" describes the type of extension. It is
recommended that user extensions follow "cert-name@domain.org" naming.

The "is_critical" indicates whether this extension is mandatory or
optional. If true, then any unsupported extension encountered should
result in KRL parsing failure. If false, then it may be safely be
ignored.

The "extension_contents" contains the body of the extension.

3. Explicit key sections

These sections, identified as KRL_SECTION_EXPLICIT_KEY, revoke keys
(not certificates). They are less space efficient than serial numbers,
but are able to revoke plain keys.

	string	public_key_blob[0]
	....

This section must contain at least one "public_key_blob". The blob
must be a raw key (i.e. not a certificate).

This section may appear multiple times.

4. SHA1/SHA256 fingerprint sections

These sections, identified as KRL_SECTION_FINGERPRINT_SHA1 and
KRL_SECTION_FINGERPRINT_SHA256, revoke plain keys (i.e. not
certificates) by listing their hashes:

	string	public_key_hash[0]
	....

This section must contain at least one "public_key_hash". The hash blob
is obtained by taking the SHA1 or SHA256 hash of the public key blob.
Hashes in this section must appear in numeric order, treating each hash
as a big-endian integer.

This section may appear multiple times.

5. Extension sections

This section type provides a generic extension mechanism to the KRL
format that may be used to provide optional or critical data.

Extensions are recorded in sections of type KRL_SECTION_EXTENSION
with the following contents:

	string	extension_name
	boolean is_critical
	string	extension_contents.

Where "extension_name" describes the type of extension. It is
recommended that user extensions follow "name@domain.org" naming.

The "is_critical" indicates whether this extension is mandatory or
optional. If true, then any unsupported extension encountered should
result in KRL parsing failure. If false, then it may be safely be
ignored.

The "extension_contents" contains the body of the extension.

6. KRL signature sections

Note: KRL signatures are not supported by OpenSSH. OpenSSH >= 9.4 will
refuse to load KRLs that contain signatures. We recommend the use
of SSHSIG (`ssh-keygen -Y sign ...`) style signatures for KRLs instead.

The KRL_SECTION_SIGNATURE section serves a different purpose to the
preceding ones: to provide cryptographic authentication of a KRL that
is retrieved over a channel that does not provide integrity protection.
Its format is slightly different to the previously-described sections:
in order to simplify the signature generation, it includes as a "body"
two string components instead of one.

	byte	KRL_SECTION_SIGNATURE
	string	signature_key
	string	signature

The signature is calculated over the entire KRL from the KRL_MAGIC
to this subsection's "signature_key", including both and using the
signature generation rules appropriate for the type of "signature_key".

This section must appear last in the KRL. If multiple signature sections
appear, they must appear consecutively at the end of the KRL file.

Implementations that retrieve KRLs over untrusted channels must verify
signatures. Signature sections are optional for KRLs distributed by
trusted means.

7. Bloom filter extensions

A number of extensions that use Bloom filters to reduce the requirement
to scan entire KRLs are described here.

Each Bloom filter extension corresponds to a revocation section or
subsection above. For all cases, the Bloom filter extension must
appear in the KRL before its corresponding revocation block.

Bloom filter set sizes must be a power of two.

7.1 Explicit key Bloom filter extension "bloom-explicit-key"

This extension section allows a KRL generator to specify a Bloom
filter containing keys in a subsequent KRL_SECTION_EXPLICIT_KEY
section. KRL consumers wishing to check a particular key may test
the Bloom filter and, if the key is not a member, skip further
processing of the subsequent KRL_SECTION_EXPLICIT_KEY section.

If this section is present, it must be before the corresponding
KRL_SECTION_EXPLICIT_KEY section and the KRL_SECTION_EXPLICIT_KEY
section must be present in the KRL.

Member keys are added to the Bloom filter by hashing their entire
key blob. This section has the following format:

	byte	KRL_SECTION_EXTENSION
	string	extension_contents

Where "extension contents" contains:

	string	"bloom-explicit-key"
	boolean FALSE (not critical)
	string	bloom filter contents

Where "bloom filter contents" is a serialized Bloom filter as
described in section 8.

7.2 Key hash Bloom filter extensions "bloom-key-hash-sha*"

These extensions allows a KRL to contain Bloom filters that correspond
to KRL_SECTION_FINGERPRINT_SHA1 and KRL_SECTION_FINGERPRINT_SHA256
sections. Similar to the "bloom-explicit-key" extension, these
extensions must appear before a section of their corresponding type.

	byte	KRL_SECTION_EXTENSION
	string	extension_contents

Where "extension contents" contains:

	string	"bloom-key-hash-sha1" or "bloom-key-hash-sha256"
	boolean FALSE (not critical)
	string	bloom filter contents

Members of the Bloom filter for these extensions are the respective
key hashes (hashed again using the Bloom filter hash). "bloom filter
contents" is a serialized Bloom filter as described in section 8.

7.2 Certificate key ID Bloom filter extension "cert-bloom-key-id"

This certificate section extension allows a KRL reader to skip
processing of a KRL_SECTION_CERT_KEY_ID subsection if the key under
test is not an element of the Bloom filter. This extension must
appear before the KRL_SECTION_CERT_KEY_ID subsection in the
certificate section of the KRL.

	byte	KRL_SECTION_CERT_EXTENSION
	string	extension_contents

Where "extension contents" contains:

	string	"cert-bloom-key-id"
	boolean FALSE (not critical)
	string	bloom filter contents

Members of the Bloom filter for these extensions are key ID strings.
"bloom filter contents" is a serialized Bloom filter as described in
section 8.

7.3 Certificate serial Bloom filter extension "cert-bloom-serial"

This certificate section extension allows a KRL reader to skip
processing of KRL_SECTION_CERT_SERIAL_* subsections if the key under
test is not an element of the Bloom filter. This extension must
appear before any KRL_SECTION_CERT_SERIAL_* subsection in the
certificate section of the KRL, and at least one such subsection must
be present following the extension.

	byte	KRL_SECTION_CERT_EXTENSION
	string	extension_contents

Where "extension contents" contains:

	string	"cert-bloom-serial"
	boolean FALSE (not critical)
	string	bloom filter contents

Members of the Bloom filter for these extensions are certificate
serial numbers converted to 64-bit big endian byte strings for
presentation to the Bloom filter hash. "bloom filter contents" is a
serialized Bloom filter as described in section 8.

8. Bloom filter serialization

Bloom filters are serialized using the following format:

	uint32 m
	uint32 k
	string hashalg
	string seed
	string bitmap

Where "m" is the number of bit members in the filter and must greater
than 1 and be a power of two, "k" is the number of hash algorithms used
per element and must be at least 1 and no more than 32, "hashalg" is the
hash algorithm in use (at present only a single algorithm is supported),
"seed" is a seed to diversify the hash algorithm and resist adversarial
hash collisions and "bitmap" is the contents of the Bloom filter bitmap
in big endian format.

9. The "sha256-ctr" hash algorithm

The algorithm "sha256-ctr" is the hash family used in the Bloom
filter sections above. As the name suggests, it is based
on SHA256.

This hash family generates integer hash values modulo the Bloom filter
size by hashing a 32 byte seed, a counter (represented as big endian
uint32), and the value to be added or tested in the set. The 256-bit
output is treated as 8 x 32-bit big endian integers that are then
reduced modulo the Bloom filter set size ('m'). If more than 8 hash
values are required then the counter is incremented for each additional
SHA256 invocation.

In pseudocode:

	ctr = 0
	while (i < k):
		raw_hash = SHA256(seed || format_uint32(ctr) || data)
		for j in range(8):
			hash_value[i] = get_uint32(raw_hash[j*4:j*4+4]) % m
			i++
		ctr++

$OpenBSD: PROTOCOL.krl,v 1.7 2023/07/17 04:01:10 djm Exp $
