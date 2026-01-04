/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.cbor;

import java.util.Arrays;

import org.webpki.crypto.CryptoException;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.HmacVerifierInterface;

/**
 * Class for CBOR HMAC signature validation.
 *<p>
 * See also {@link CBORValidator}.
 *</p>
 */
public class CBORHmacValidator extends CBORValidator<CBORHmacValidator> {
    
    HmacVerifierInterface verifier;

    CBORHmacValidator(HmacVerifierInterface verifier, boolean externalInterface) {
        super(externalInterface);
        this.verifier = verifier;
    }

    /**
     * Creates a validator object with a secret key.
     * <p>
     * This constructor presumes that the validation key is given by the context
     * and that the supplied algorithm meets the policy.  The optional CSF
     * <code>keyId</code> is <i>ignored</i>.
     * </p>
     * 
     * @param secretKey Validation key
     */
    public CBORHmacValidator(byte[] secretKey) {
        this((data, digest, algorithm, keyId) -> 
            Arrays.equals(algorithm.digest(secretKey, data), digest), false);
    }

    /**
     * Creates a validator object with an external implementation.
     * <p>
     * This constructor provides full control for the verifier
     * HMAC algorithms and cryptographic providers.  Note that an optional CSF
     * <code>keyId</code> <b>must</b> be a CBOR string.
     * </p>
     *
     * @param verifier Verifier implementation
     */
    public CBORHmacValidator(HmacVerifierInterface verifier) {
        this(verifier, true);
    }

    @Override
    void coreValidation(CBORMap csfContainer, 
                        int coseAlgorithmId,
                        CBORObject optionalKeyId,
                        byte[] signatureValue,
                        byte[] signedData) {
        if (!verifier.verify(signedData, 
                             signatureValue, 
                             HmacAlgorithms.getAlgorithmFromId(coseAlgorithmId),
                             optionalKeyId == null ? null : optionalKeyId.getString())) {
            throw new CryptoException("HMAC signature validation error");
        }
    }

    @Override
    CBORHmacValidator getThis() {
        return this;
    }
}
