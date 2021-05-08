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
package org.webpki.json;

import java.io.IOException;

import java.security.GeneralSecurityException;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

/**
 * Initiator object for symmetric key signatures.
 */
public class JSONSymKeySigner extends JSONSigner {

    SymKeySignerInterface signer;

    /**
     * Constructor for custom crypto solutions.
     * @param signer Handle to implementation
     * @throws IOException
     * @throws GeneralSecurityException 
     */
    public JSONSymKeySigner(SymKeySignerInterface signer) throws IOException,
                                                                 GeneralSecurityException {
        this.signer = signer;
    }

    /**
     * Constructor for JCE based solutions.
     * @param rawKey Key
     * @param algorithm MAC algorithm
     * @throws IOException
     */
    public JSONSymKeySigner(final byte[] rawKey, final HmacAlgorithms algorithm) 
            throws IOException {
        signer = new SymKeySignerInterface() {

            @Override
            public byte[] signData(byte[] data) throws IOException, GeneralSecurityException {
                return algorithm.digest(rawKey, data);
            }

            @Override
            public HmacAlgorithms getAlgorithm() throws IOException {
                return algorithm;
            }

            @Override
            public void setAlgorithm(HmacAlgorithms algorithm)
                    throws IOException, GeneralSecurityException {
            }
           
        };
    }

    public JSONSymKeySigner setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
        this.algorithmPreferences = algorithmPreferences;
        return this;
    }

    @Override
    SignatureAlgorithms getAlgorithm() throws IOException, GeneralSecurityException {
        return signer.getAlgorithm();
    }

    @Override
    byte[] signData(byte[] data) throws IOException, GeneralSecurityException {
        return signer.signData(data);
    }

    @Override
    void writeKeyData(JSONObjectWriter wr) throws IOException {
    }
}
