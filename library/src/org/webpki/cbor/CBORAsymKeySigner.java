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

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.crypto.signatures.SignatureWrapper;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for creating CBOR asymmetric key signatures.
 * 
 * It uses COSE algorithms but relies on CSF for the packaging.
 * 
 * Note that signer objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 */
public class CBORAsymKeySigner extends CBORSigner {

    AsymSignatureAlgorithms algorithm;
    
    PublicKey optionalPublicKey;
    
    AsymKeySignerInterface signer;

    /**
     * Initializes signer.
     * 
     * @param signer Custom signer
     * @throws GeneralSecurityException 
     * @throws IOException 
     */
    public CBORAsymKeySigner(AsymKeySignerInterface signer) throws IOException,
                                                                   GeneralSecurityException {
        this.signer = signer;
        setAlgorithm(signer.getAlgorithm());
    }
    
    /**
     * Initialize signer with a private key.
     * 
     * The default signature algorithm to use is based on the recommendations
     * in RFC 7518.
     * 
     * @param privateKey The key to sign with
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public CBORAsymKeySigner(PrivateKey privateKey) throws IOException, GeneralSecurityException {
        
        signer = new AsymKeySignerInterface() {

            @Override
            public byte[] signData(byte[] dataToBeSigned) throws IOException,
                                                                 GeneralSecurityException {
                return new SignatureWrapper(algorithm, privateKey, provider)
                        .update(dataToBeSigned)
                        .sign();            
            }
            
        };
        setAlgorithm(KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm());
    }

    /**
     * Puts a public key into the signature container.
     * 
     * <p>
     * Note that a public key value of <code>null</code> 
     * is equivalent to the default (=no public key).
     * </p>
     * 
     * 
     * @param publicKey The public key or <code>null</code>
     * @return this
     */
    public CBORAsymKeySigner setPublicKey(PublicKey publicKey) {
        optionalPublicKey = publicKey;
        return this;
    }
    
    /**
     * Sets signature algorithm.
     * 
     * @param algorithm The algorithm
     * @return this
     * @throws GeneralSecurityException 
     * @throws IOException 
     */
    public CBORAsymKeySigner setAlgorithm(AsymSignatureAlgorithms algorithm) throws IOException {
        this.algorithm = algorithm;
        this.coseAlgorithmId = algorithm.getCoseAlgorithmId();
        return this;
    }    

    @Override
    byte[] signData(byte[] dataToBeSigned) throws IOException, GeneralSecurityException {
        return signer.signData(dataToBeSigned);
    }

    @Override
    void additionalItems(CBORMap signatureObject) throws IOException, GeneralSecurityException {
        if (optionalPublicKey != null) {
            signatureObject.setObject(PUBLIC_KEY_LABEL, CBORPublicKey.encode(optionalPublicKey));
            checkKeyId(optionalKeyId);
        }
    }
}
