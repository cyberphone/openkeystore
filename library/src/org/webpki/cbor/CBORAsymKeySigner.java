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

import java.security.PrivateKey;
import java.security.PublicKey;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for creating CBOR asymmetric key signatures.
 * <p>
 * Also see {@link CBORSigner}.
 * </p>
 * <p> 
 * Note that asymmetric key signatures do not permit using
 * both a <code>keyId</code> and an in-line public key.
 * Also see {@link CBORSigner#setKeyId(CBORObject)} and {@link #setPublicKey(PublicKey)}.
 * </p>
 */
public class CBORAsymKeySigner extends CBORSigner {

    PublicKey optionalPublicKey;
    
    AsymKeySignerInterface signer;

    /**
     * Initializes a signer with an external interface.
     * 
     * @param signer Custom signer
     */
    public CBORAsymKeySigner(AsymKeySignerInterface signer) {
        this.signer = signer;
    }
    
    /**
     * Initializes a signer with a private key.
     * <p>
     * The default signature algorithm to use is based on the recommendations
     * in RFC 7518.
     * </p>
     * @param privateKey Signature key
     */
    public CBORAsymKeySigner(PrivateKey privateKey) {
        this(privateKey, 
             KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm());
    }

    /**
     * Initializes a signer with a private key.
     * 
     * @param privateKey Signature key
     * @param algorithm Signature algorithm
     */
    public CBORAsymKeySigner(PrivateKey privateKey, AsymSignatureAlgorithms algorithm) {
        
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

    /**
     * Puts a public key into the signature container.
     * 
     * <p>
     * Note that a public key value of <code>null</code> 
     * is equivalent to the default (=no public key).
     * </p>
     * 
     * @param publicKey The public key or <code>null</code>
     * @return <code>this</code>
     */
    public CBORAsymKeySigner setPublicKey(PublicKey publicKey) {
        optionalPublicKey = publicKey;
        return this;
    }
    
    @Override
    byte[] coreSigner(byte[] dataToBeSigned) {
        return signer.signData(dataToBeSigned);
    }

    @Override
    void additionalItems(CBORMap signatureObject) {
        if (optionalPublicKey != null) {
            signatureObject.set(PUBLIC_KEY_LABEL, CBORPublicKey.convert(optionalPublicKey));
            CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
        }
    }

    @Override
    SignatureAlgorithms getAlgorithm() {
        return signer.getAlgorithm();
    }
}
