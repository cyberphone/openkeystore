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
import java.security.PublicKey;

import org.webpki.crypto.CryptoRandom;
import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;
import org.webpki.crypto.encryption.EncryptionCore;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;

/**
 * Class for creating CBOR asymmetric key encryptions.
 * 
 * It uses COSE algorithms but not the packaging.
 * 
 * Note that encrypters may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 */
public class CBORAsymKeyEncrypter extends CBOREncrypter {

    KeyEncryptionAlgorithms keyEncryptionAlgorithm;

    boolean wantPublicKey;
    PublicKey publicKey;
    
    /**
     * Initialize encrypter.
     * 
     * @param publicKey The key to encrypt with
     * @param keyEncryptionAlgorithm KEK algorithm
     * @param contentEncryptionAlgorithm Actual encryption algorithm
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORAsymKeyEncrypter(PublicKey publicKey,
                                KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                ContentEncryptionAlgorithms contentEncryptionAlgorithm) 
            throws IOException, GeneralSecurityException {
        super(contentEncryptionAlgorithm);
        this.publicKey = publicKey;
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
    }

    /**
     * Define if public key should be included.
     * 
     * @param wantPublicKey Flag.  Default: false.
     * @return this
     */
    public CBORAsymKeyEncrypter setPublicKeyOption(boolean wantPublicKey) {
        this.wantPublicKey = wantPublicKey;
        return this;
    }
 
    @Override
    byte[] getContentEncryptionKey(CBORMap keyEncryption)
            throws IOException, GeneralSecurityException {
        
        // The mandatory key encryption algorithm
        keyEncryption.setObject(ALGORITHM_LABEL,
                                new CBORInteger(keyEncryptionAlgorithm.getCoseAlgorithmId()));
        
        // We may want to include the public key as well
        if (wantPublicKey) {
            keyEncryption.setObject(PUBLIC_KEY_LABEL,
                                    CBORPublicKey.encode(publicKey));
        }
        
        // Key wrapping algorithms need a key to wrap
        byte[] contentEncryptionKey = keyEncryptionAlgorithm.isKeyWrap() ?
            CryptoRandom.generateRandom(contentEncryptionAlgorithm.getKeyLength()) : null;
                                                                         
        // The real stuff...
        EncryptionCore.AsymmetricEncryptionResult asymmetricEncryptionResult =
                keyEncryptionAlgorithm.isRsa() ?
                    EncryptionCore.rsaEncryptKey(contentEncryptionKey,
                                                 keyEncryptionAlgorithm,
                                                 publicKey)
                                               :
                    EncryptionCore.senderKeyAgreement(true,
                                                      contentEncryptionKey,
                                                      keyEncryptionAlgorithm,
                                                      contentEncryptionAlgorithm,
                                                      publicKey);
        if (!keyEncryptionAlgorithm.isRsa()) {
            // ECDH-ES requires the ephemeral public key
            keyEncryption.setObject(EPHEMERAL_KEY_LABEL,
                                    CBORPublicKey.encode(
                                        asymmetricEncryptionResult.getEphemeralKey()));
        }
        if (keyEncryptionAlgorithm.isKeyWrap()) {
            // Encrypted key
            keyEncryption.setObject(CIPHER_TEXT_LABEL,
                                    new CBORByteString(
                                        asymmetricEncryptionResult.getEncryptedKeyData()));
        }
        return asymmetricEncryptionResult.getContentEncryptionKey();
    }
    
    @Override
    CBORMap getEncryptionObject(CBORMap original) throws IOException {
        CBORMap keyEncryption = new CBORMap();
        original.setObject(KEY_ENCRYPTION_LABEL, keyEncryption);
        return keyEncryption;
    }
}
