/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.cbor;

import java.io.IOException;

import java.security.GeneralSecurityException;

import org.webpki.crypto.HmacAlgorithms;

import org.webpki.util.ArrayUtil;

/**
 * Class for CBOR HMAC signature validation.
 *<p>
 * See {@link CBORValidator} for details.
 *</p>
 */
public class CBORHmacValidator extends CBORValidator {
    
    /**
     * For dynamic key retrieval.
     */
    public interface KeyLocator {

        /**
         * Check signature data and retrieve validation key.
         * <p>
         * An implementation is supposed to throw an exception if it
         * does not find a matching key or if the supplied algorithm does
         * not meet the policy.
         * </p>
         * 
         * @param optionalKeyId KeyId or null
         * @param algorithm HMAC algorithm
         * @return Validation key 
         * @throws IOException
         * @throws GeneralSecurityException
         */
        byte[] locate(CBORObject optionalKeyId, HmacAlgorithms algorithm)
            throws IOException, GeneralSecurityException;
    }
    
    KeyLocator keyLocator;

    /**
     * Initializes a validator with a secret key.
     * 
     * Using this option the algorithm provided by the
     * producer is supposed to be correct.  The alternative
     * constructor gives the validator full control.
     * 
     * @param secretKey Validation key
     */
    public CBORHmacValidator(byte[] secretKey) {
        this(new KeyLocator() {

            @Override
            public byte[] locate(CBORObject optionalKeyId, HmacAlgorithms hmacAlgorithm) {
                 return secretKey;
            }
            
        });
    }

    /**
     * Initializes a validator with a key locator.
     * 
     * This option provides full control for the verifier
     * regarding key identifiers and HMAC algorithms.
     *
     * @param keyLocator The call back
     */
    public CBORHmacValidator(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }

    @Override
    void coreValidation(CBORMap signatureObject, 
                        int coseAlgorithmId,
                        CBORObject optionalKeyId,
                        byte[] signatureValue,
                        byte[] signedData) throws IOException, GeneralSecurityException {
        // Get algorithm from the signature object.
        HmacAlgorithms hmacAlgorithm = HmacAlgorithms.getAlgorithmFromId(coseAlgorithmId);

        // Finally, verify the HMAC.
        if (!ArrayUtil.compare(hmacAlgorithm.digest(
                keyLocator.locate(optionalKeyId, hmacAlgorithm), signedData), signatureValue)) {
            throw new GeneralSecurityException("HMAC signature validation error");
        }
    }
}
