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

import org.webpki.crypto.encryption.EncryptionCore;
import org.webpki.crypto.encryption.KeyEncryptionAlgorithms;

/**
 * Class for CBOR asymmetric key decryption.
 * 
 * Note that decrypter objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe. 
 */
public class CBORAsymKeyDecrypter extends CBORDecrypter {
    
    /**
     * For dynamic key retrieval.
     */
    public interface KeyLocator {

        /**
         * Lookup private decryption key.
         * 
         * @param optionalPublicKey Optional public key found in the signature object
         * @param optionalKeyId KeyId or <code>null</code>
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @return Private key for decryption
         * @throws IOException
         * @throws GeneralSecurityException
         */
        PrivateKey locate(PublicKey optionalPublicKey, 
                          String optionalKeyId, 
                          KeyEncryptionAlgorithms keyEncryptionAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    KeyLocator keyLocator;
    
    /**
     * Initialize decrypter with private key.
     * 
     * @param optionalPublicKey The anticipated public key
     */
    public CBORAsymKeyDecrypter(PrivateKey privateKey) {
        this(new KeyLocator() {

            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     String optionalKeyId,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm)
                    throws IOException, GeneralSecurityException {
                return privateKey;
            }
            
        });
    }

    /**
     * Initialize decrypter with a locator.
     * 
     * This option provides full control for the verifier
     * regarding in-lined public keys and key identifiers.
     * <p>
     * If no public key is found in the signature object, 
     * the {@link KeyLocator} will be called BEFORE signature validation
     * with a <code>null</code> public key argument.  This permits
     * applications to retrieve a suitable key for validation.
     * This is usually done by requiring a key identifier.
     * </p>
     * <p>
     * If on the other a public is found in the signature object,
     * it will be used for signature validation.  AFTER successful
     * signature validation, the {@link KeyLocator} will be called
     * with the public key argument holding the public key of
     * the signature object.  This permits applications to first
     * validate the signature and then lookup the key which may
     * simplify database design. 
     * </p>
     * 
     * @param keyLocator The call back
     */
    public CBORAsymKeyDecrypter(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }
    
    @Override
    void keyEncryption(CBORIntegerMap innerObject) throws IOException, GeneralSecurityException {
        PrivateKey privateKey = keyLocator.locate(optionalPublicKey,
                                                  optionalKeyId,
                                                  keyEncryptionAlgorithm);
        if (keyEncryptionAlgorithm.isRsa()) {
            contentDecryptionKey = EncryptionCore.rsaDecryptKey(keyEncryptionAlgorithm, 
                                                                encryptedKey,
                                                                privateKey);
            return;
        }
        contentDecryptionKey = EncryptionCore.receiverKeyAgreement(keyEncryptionAlgorithm,
                                                                   contentEncryptionAlgorithm,
                                                                   ephemeralKey,
                                                                   privateKey,
                                                                   encryptedKey);
    }
}
