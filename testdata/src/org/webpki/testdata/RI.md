## Deviations from the JOSE stack
The JSF (JSON Signature Format) and JEF (JSON Encryption Format) specifications inherit most features from
their JOSE counterparts JWS and JWE respectively but some have been left out since they have
been found to be redundant and/or quirky.

The syntax is though quite different since the container is different.

### Subset: JWK Support
JSF and JEF specify that JWKs hold public keys and _no other data_.
However, if you look into the actual JWK specification, it can host a variety
of other data.

### Dropped: JKU Header Support
The JKU header may at first sight seem like cool idea but it is not because
it is either _underspecified_ (needs a KID in _both_ ends to be used),
or require "unusual" tricks like testing a set of JWKS-supplied keys for a match.

In most real world applications, there are very specific requirements on what to accept
as key indicators which makes KID ("KeyId" in this specification) entirely sufficient
for locating keys; it might be an URL as well. 

### Dropped: X5U Header Support
In most real world applications, there are very specific requirements on what to accept
as key indicators which makes KID ("KeyId" in this specification) entirely sufficient
for locating keys; it might be an URL as well. 

### Dropped: Union Header
JWS and JWE support the UNION of outer and inner header parameters for the multi use case,
JSF and JEF do not since the added value is very limited.

### Multi Encryption Limitations
In theory you can use ECDH in a multi encryption setup but since it can only
support a single recipient, this algorithm is unsupported by the JEF for
usage with the multi encryption scheme.

That is, JEF only allows _key wrapping algorithms_ for multi encryption.

### Dropped: Support for Partial Success
How many signatures that must be valid in a multi-signature scheme is a _policy_.
In this specific implementation _all_ signatures must be valid. 
