## Deviations from the Cleartext JWS/JWE Specifications
The Cleartext JWS and JWE specifications inherit most of their features from
the original JWS and JWE specifications.

Some of these features are (IMO) neither good nor useful and have therefore no
support in my RI ("reference implementation").


### JWK Support
JWS and JWE claim that JWKs hold public keys.
However, if you look into the actual JWK specification, it can host a variety
of other data.

The RI only supports JWKs holding a single public key and _no other
data_.

### JKU Header Support
The JKU header may at first sight seem like cool idea but it is not because
it is either _underspecified_ (needs a KID in _both_ ends to be used),
or require "unusual" tricks like testing a set of keys for a match.

That is, the RI indeed implements support for JKU but _requires that the addressed JWKS only has a single element_.

It is beyond my understanding what a _legitmate_ use-case for JKU is for JWE but the RI supports it anyway.

In fact, even for JWS, JKU seems like a quite limited solution.  Both OpenID and Saturn
which depend on server based keys, therefore communicate URLs trough _other means_,
which also offer richer information.

### Union Header Weirdness
JWS and JWE support the UNION of outer and inner header parameters for the multi use case, the RI does not.

Why is that?  In order to make use of this feature you would end-up with a rather
strange API where you would deal with header data separately.  Another aspect is
that the gain is zero since it just introduces another way of doing the same thing here shown
using a signature:

```code
{
  "iss": "joe",
  "__cleartext_signature": {
    "kid": "example.com:p256",
    "signers": [{
      "alg": "ES256",
      "signature": "pXP0GFHms0SntctNk1G1pHZfccVYdZkmAJktY_hpMsIAckzX7wZJIJNlsBzmJ1_7LmKATiW-YHHZjsYdT96JZw"
    }]
  }
}
```

Therefore the RI limits outer level support to ALG and non-crypto headers such as CRIT.

### Multi Encryption Limitations
In theory you can use ECDH in a multi encryption setup but since it can only
support a single recipient, this algorithm is unsupported by the RI for
usage with the multi encryption scheme.

That is, the RI only allows _key wrapping algorithms_ for multi encryption.

### Support for Partial Success
The RI requires that _all_ operations carry out correctly, otherwise it throws an exception.

This is not in conflict with the specification, it is just a _reasonable_
application limitation.
