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

    AsymSignatureAlgorithms algorithm;

    AsymKeySignerInterface signer;

    PublicKey publicKey;

    /**
     * Constructor for custom crypto solutions.
     * 
     * @param signer Handle to implementation
     */
    public JSONAsymKeySigner(AsymKeySignerInterface signer) {
        this.signer = signer;
        this.algorithm = signer.getAlgorithm();
    }
    
    /**
     * Constructor for JCE based solutions.

     * @param privateKey Private key
     */
    public JSONAsymKeySigner(PrivateKey privateKey) {
        algorithm = KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm();
        signer = new AsymKeySignerInterface() {

            @Override
            public byte[] signData(byte[] data) {
                return SignatureWrapper.sign(privateKey, algorithm, data, provider);
            }

            @Override
            public AsymSignatureAlgorithms getAlgorithm() {
                return algorithm;
            }
          
        };
    }

    public JSONAsymKeySigner setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public JSONAsymKeySigner setAlgorithm(AsymSignatureAlgorithms algorithm) {
        this.algorithm = algorithm;
        return this;
    }
    
    public JSONAsymKeySigner setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
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
        if (publicKey != null) {
            wr.setPublicKey(publicKey, algorithmPreferences);
        }
    }
}
