# what hash to use

options:

1. negotiate hash via kex pseudoalg, e.g kex2025-sha256-c
2. pick up KEX hash and use that

1 means that the negotiated hash might be stronger or weaker than the KEX
hash, or potentially to require a limited-algorithm SSH implementation to
have to support a hash algorithm it doesn't otherwise need.

2 is trickier to do properly.

Decision: went with 2, but excluded KEXINIT from the transcript hash.
KEXINIT is included in the exchange hash already, so it's not lost.
This means we can start the transcript *after* KEX algorithm matching
because we can wait for both the client and server KEXINITs and use this
to choose the transcript hash algorithm. 

This does means that we need strict-KEX style guarantees that KEXINIT is
the first message.

# initial vs all?

Should this be limited to the initial KEX or should it apply to reKEX as well?

Decision: went with all, for consistency. Given that we start the transcript
at the point of KEXINIT matching, the protocol is guaranteed to be KEX
messages only at that point, so it's not going to be hashing large amounts
of session data.

# when to stop the transcript

I went with finalising the transcript in each endpoint immediately after
it sends its final KEX message before it sends/expects the reply with the
server's hostkey signature.

Not sure about this. Maybe it should finalise a bit later. This is mostly
a code organisation problem.

**TODO**

# what to include in the transcript

At the moment it's full packets: [len, padlen, type, body].

Maybe it should be just [len, type, body]. That could let us stuff KEXINIT
in there.

**TODO**

# what goes in the exchange hash?

Currently the transcripts are in addition to the KEXINIT packets.
They could replace the KEXINIT packets, but I don't think so.

**TODO**

# what gets signed?

The server's signature is still over the hash. Maybe this should change
while we're in here? It could be an opportunity for putting some structure
in the signature.

Also should sign the initial and most recent exchange hash during rekex

Rationale: domain separation for the signature, possibility of keys being
made available for server host key use only.

**TODO**

# how are keys derived?

When full-transcript hash KEX modes are in use, the KDF used to derive
the actual cipher/MAC keys is switched from the custom RFC4253 hash-based
KDF to RFC5869 HKDF.

Rationale: HKDF is a well-understood construct that has had a lot of scrutiny.

**TODO**

# do full-transcript KEX modes imply strict KEX?

IMO yes.

Rationale: it's more conservative and makes mistakes much harder to
exploit.

# do full-transcript modes imply EXT_INFO

IMO yes

Rationale: it set us up for a future where a SSH implementation that
offers only FTH modes doesn't need extra crap in kex_algoritms.

**TODO**


