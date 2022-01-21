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
import org.webpki.crypto.HmacSignerInterface;

/**
 * Class for creating CBOR HMAC signatures.
 * 
 * It uses COSE algorithms but relies on CSF for the packaging.
 * 
 * Note that signer objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 */
public class CBORHmacSigner extends CBORSigner {

    HmacSignerInterface signer;

    /**
     * Initializes signer.
     * 
     * @param secretKey The key to sign with
     * @param algorithm The algorithm to use
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public CBORHmacSigner(byte[] secretKey, HmacAlgorithms algorithm) 
            throws IOException, GeneralSecurityException {
        
        this.signer = new HmacSignerInterface() {

            @Override
            public byte[] signData(byte[] data) throws IOException, GeneralSecurityException {
                return algorithm.digest(secretKey, data);
            }
            
        };
        setAlgorithm(algorithm);
     }
    
    /**
     * Initializes signer with an external interface.
     * 
     * @param signer The external signer
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public CBORHmacSigner(HmacSignerInterface signer) throws IOException,
                                                             GeneralSecurityException {
        this.signer = signer;
        setAlgorithm(signer.getAlgorithm());
    }
    
    /**
     * Sets signature algorithm.
     * 
     * @param algorithm The algorithm
     * @return this
     */
    public CBORHmacSigner setAlgorithm(HmacAlgorithms algorithm) {
        this.coseAlgorithmId = algorithm.getCoseAlgorithmId();
        return this;
    }  
    
    @Override
    byte[] signData(byte[] dataToBeSigned) throws IOException, GeneralSecurityException {
        return signer.signData(dataToBeSigned);
    }

    @Override
    void additionalItems(CBORMap signatureObject) throws IOException, GeneralSecurityException {
        // No additional items needed.
    }
}
