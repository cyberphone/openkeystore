/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

import java.io.IOException;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

/**
 * Initiator object for symmetric key signatures.
 */
public class JSONSymKeySigner extends JSONSigner {

    private static final long serialVersionUID = 1L;

    HmacAlgorithms algorithm;

    SymKeySignerInterface signer;

    /**
     * Constructor for custom crypto solutions.
     * @param signer Handle to implementation
     * @throws IOException &nbsp;
     */
    public JSONSymKeySigner(SymKeySignerInterface signer) throws IOException {
        this.signer = signer;
        algorithm = signer.getHmacAlgorithm();
    }

    /**
     * Constructor for JCE based solutions.
     * @param rawKey Key
     * @param algorithm MAC algorithm
     * @throws IOException &nbsp;
     */
    public JSONSymKeySigner(final byte[] rawKey, final HmacAlgorithms algorithm) throws IOException {
        this(new SymKeySignerInterface() {

            @Override
            public byte[] signData(byte[] data, HmacAlgorithms algorithm) throws IOException {
                return algorithm.digest(rawKey, data);
            }

            @Override
            public HmacAlgorithms getHmacAlgorithm() throws IOException {
                return algorithm;
            }
           
        });
    }

    public JSONSymKeySigner setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
        this.algorithmPreferences = algorithmPreferences;
        return this;
    }

    @Override
    SignatureAlgorithms getAlgorithm() {
        return algorithm;
    }

    @Override
    byte[] signData(byte[] data) throws IOException {
        return signer.signData(data, algorithm);
    }

    @Override
    void writeKeyData(JSONObjectWriter wr) throws IOException {
    }
}
