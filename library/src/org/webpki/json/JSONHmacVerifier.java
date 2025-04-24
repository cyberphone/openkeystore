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
package org.webpki.json;

import java.util.Arrays;

import org.webpki.crypto.CryptoException;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.HmacVerifierInterface;

/**
 * Initiator object for HMAC signature verifiers.
 */
public class JSONHmacVerifier extends JSONVerifier {

    HmacVerifierInterface verifier;

    /**
     * Custom crypto verifier for symmetric keys.
     * Note that you can access the received KeyIi from {@link JSONSignatureDecoder}.
     *
     * @param verifier Handle to implementation
     */
    public JSONHmacVerifier(HmacVerifierInterface verifier) {
        super(JSONSignatureTypes.SYMMETRIC_KEY);
        this.verifier = verifier;
    }

    /**
     * JCE based verifier for symmetric keys.
     * Note that you can access the received KeyId from {@link JSONSignatureDecoder}.
     *
     * @param rawKey Key
     */
    public JSONHmacVerifier(final byte[] rawKey) {
        this(new HmacVerifierInterface() {

            @Override
            public boolean verify(byte[] data,
                                  byte[] digest,
                                  HmacAlgorithms algorithm,
                                  String keyId) {
                return Arrays.equals(digest, algorithm.digest(rawKey, data));
            }
            
        });
    }

    @Override
    void verify(JSONSignatureDecoder signatureDecoder) {
        if (!verifier.verify(signatureDecoder.normalizedData,
                             signatureDecoder.signatureValue,
                             (HmacAlgorithms) signatureDecoder.signatureAlgorithm,
                             signatureDecoder.keyId)) {
            throw new CryptoException("Bad signature for key: " + signatureDecoder.keyId);
        }
    }
}
