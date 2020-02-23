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

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.PrivateKey;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

/**
 * Initiator object for asymmetric key signatures.
 */
public class JSONAsymKeySigner extends JSONSigner {

    private static final long serialVersionUID = 1L;

    AsymSignatureAlgorithms algorithm;

    AsymKeySignerInterface signer;

    PublicKey publicKey;

    /**
     * Constructor for custom crypto solutions.
     * @param signer Handle to implementation
     * @throws IOException &nbsp;
     */
    public JSONAsymKeySigner(AsymKeySignerInterface signer) throws IOException {
        this.signer = signer;
        publicKey = signer.getPublicKey();
        algorithm = KeyAlgorithms.getKeyAlgorithm(publicKey).getRecommendedSignatureAlgorithm();
    }

    /**
     * Constructor for JCE based solutions.
     * @param privateKey Private key
     * @param publicKey Public key
     * @param provider Optional JCE provider or null
     * @throws IOException &nbsp;
     */
    public JSONAsymKeySigner(final PrivateKey privateKey,
                             final PublicKey publicKey,
                             final String provider) throws IOException {
        this(new AsymKeySignerInterface() {

            @Override
            public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
                try {
                    return new SignatureWrapper(algorithm, privateKey, provider).update(data).sign();
                } catch (GeneralSecurityException e) {
                    throw new IOException(e);
                }
            }

            @Override
            public PublicKey getPublicKey() throws IOException {
                 return publicKey;
            }
            
        });
    }

    public JSONAsymKeySigner setSignatureAlgorithm(AsymSignatureAlgorithms algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public JSONAsymKeySigner setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
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
        wr.setPublicKey(publicKey, algorithmPreferences);
    }
}
