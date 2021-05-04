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
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.HashMap;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;

/**
 * Class for creating CBOR asymmetric key signatures.
 */
public class CBORAsymKeySigner extends CBORSigner {

    PrivateKey privateKey;

    AsymSignatureAlgorithms signatureAlgorithm;
    
    static final HashMap<AsymSignatureAlgorithms, Integer> asymSignatureAlgorithms = 
            new HashMap<>();
    
    static {
        asymSignatureAlgorithms.put(AsymSignatureAlgorithms.ECDSA_SHA256, ECDSA_SHA256);
    }

    /**
     * Initialize signer.
     * 
     * Note that a signer object may be used any number of times
     * (assuming that the same parameters are valid).  It is also
     * thread-safe.
     * @param privateKey The key to sign with
     * @param signatureAlgorithm The algorithm to use
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public CBORAsymKeySigner(PrivateKey privateKey,
                             AsymSignatureAlgorithms signatureAlgorithm) throws IOException {
        this.privateKey = privateKey;
        this.signatureAlgorithm = signatureAlgorithm;
        this.algorithmId = asymSignatureAlgorithms.get(signatureAlgorithm);
    }
    
    /**
     * Initialize signer.
     * 
     * Note that a signer object may be used any number of times
     * (assuming that the same parameters are valid).  It is also
     * thread-safe.
     * The default signature algorithm to use is based on the recommendations
     * in RFC 7518.
     * @param privateKey The key to sign with
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public CBORAsymKeySigner(PrivateKey privateKey) throws IOException {
        this(privateKey,
             KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm());
    }

    public CBORAsymKeySigner setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    @Override
    byte[] signData(byte[] dataToBeSigned) throws GeneralSecurityException, IOException {
        return new SignatureWrapper(signatureAlgorithm, privateKey, provider)
                .update(dataToBeSigned)
                .sign();
    }
}
