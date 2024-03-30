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

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.HmacSignerInterface;

/**
 * Initiator object for HMAC signatures.
 */
public class JSONHmacSigner extends JSONSigner {

    HmacSignerInterface signer;

    /**
     * Constructor for custom crypto solutions.
     * @param signer Handle to implementation
     */
    public JSONHmacSigner(HmacSignerInterface signer) {
        this.signer = signer;
    }

    /**
     * Constructor for JCE based solutions.
     * @param rawKey Key
     * @param algorithm MAC algorithm
     */
    public JSONHmacSigner(final byte[] rawKey, final HmacAlgorithms algorithm) {
        signer = new HmacSignerInterface() {

            @Override
            public byte[] signData(byte[] data) {
                return algorithm.digest(rawKey, data);
            }

            @Override
            public HmacAlgorithms getAlgorithm() {
                return algorithm;
            }

        };
    }

    public JSONHmacSigner setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
        this.algorithmPreferences = algorithmPreferences;
        return this;
    }

    @Override
    SignatureAlgorithms getAlgorithm() {
        return signer.getAlgorithm();
    }

    @Override
    byte[] signData(byte[] data) {
        return signer.signData(data);
    }

    @Override
    void writeKeyData(JSONObjectWriter wr) {
    }
}
