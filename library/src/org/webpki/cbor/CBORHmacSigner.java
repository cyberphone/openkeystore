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

import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.HmacSignerInterface;
import org.webpki.crypto.SignatureAlgorithms;

/**
 * Class for creating CBOR HMAC signatures.
 * <p>
 * Also see {@link CBORSigner}.
 * </p>
 */
public class CBORHmacSigner extends CBORSigner {

    HmacSignerInterface signer;

    /**
     * Initializes a signer with a secret key.
     * 
     * @param secretKey Signature key
     * @param algorithm HMAC algorithm
     */
    public CBORHmacSigner(byte[] secretKey, HmacAlgorithms algorithm) {
        
        this.signer = new HmacSignerInterface() {

            @Override
            public byte[] signData(byte[] data) {
                return algorithm.digest(secretKey, data);
            }

            @Override
            public HmacAlgorithms getAlgorithm() {
                return algorithm;
            }
            
        };
    }
    
    /**
     * Initializes signer with an external interface.
     * 
     * @param signer The external signer
     */
    public CBORHmacSigner(HmacSignerInterface signer) {
        this.signer = signer;
    }
    
    @Override
    byte[] coreSigner(byte[] dataToBeSigned) {
        return signer.signData(dataToBeSigned);
    }

    @Override
    void additionalItems(CBORMap signatureObject) {
        // No additional items needed.
    }

    @Override
    SignatureAlgorithms getAlgorithm() {
        return signer.getAlgorithm();
    }
}
