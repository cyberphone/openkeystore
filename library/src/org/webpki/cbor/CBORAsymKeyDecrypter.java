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

import java.security.PrivateKey;
import java.security.PublicKey;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for asymmetric key decryption.
 */
public class CBORAsymKeyDecrypter extends CBORDecrypter {
    
    /**
     * Decrypter engine implementation interface.
     */
    public interface DecrypterImpl {

        /**
         * Locates private decryption key.
         * <p>
         * Implementations should preferably throw {@link org.webpki.crypto.CryptoException} for
         * errors related to cryptography and security.
         * </p>
         *<p>
         * This interface also enables encryption parameter verification.
         * </p>
         *          * 
         * @param optionalPublicKey Optional public key found in the encryption object
         * @param optionalKeyId Optional key Id found in the encryption object
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Private decryption key.
         */
        PrivateKey locate(PublicKey optionalPublicKey, 
                          CBORObject optionalKeyId,
                          KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                          ContentEncryptionAlgorithms contentEncryptionAlgorithm);
 
        /**
         * Decrypts encrypted key.
         * <p>
         * Implementations should preferably throw {@link org.webpki.crypto.CryptoException} for
         * errors related to cryptography and security.
         * </p>
         *          * 
         * @param privateKey The private decryption key
         * @param optionalEncryptedKey Optional encrypted key
         * @param optionalEphemeralKey Optional ephemeral key
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Decrypted key.
         */
        byte[] decrypt(PrivateKey privateKey, 
                       byte[] optionalEncryptedKey,
                       PublicKey optionalEphemeralKey,
                       KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                       ContentEncryptionAlgorithms contentEncryptionAlgorithm);

    }
    
    DecrypterImpl decrypterImpl;
    
    /**
     * Initializes a decrypter with a private key.
     * <p>
     * This constructor presumes that the decryption key is given by the context.
     * </p>
     * @param privateKey Decryption key
     */
    public CBORAsymKeyDecrypter(PrivateKey privateKey) {
        this(new DecrypterImpl() {

            @Override
            public byte[] decrypt(PrivateKey privateKey,
                                  byte[] optionalEncryptedKey,
                                  PublicKey optionalEphemeralKey,
                                  KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                  ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                return EncryptionCore.decryptKey(true,
                                                 privateKey,
                                                 optionalEncryptedKey,
                                                 optionalEphemeralKey,
                                                 keyEncryptionAlgorithm,
                                                 contentEncryptionAlgorithm);
            }

            @Override
            public PrivateKey locate(PublicKey optionalPublicKey,
                                     CBORObject optionalKeyId,
                                     KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                                     ContentEncryptionAlgorithms contentEncryptionAlgorithm) {
                // The default implementation does not have to locate anything...
                return privateKey;
            }
             
        });
    }

    /**
     * Initializes a decrypter with a decrypter interface.
     * 
     * @param decrypterImpl Decrypter implementation
     */
    public CBORAsymKeyDecrypter(DecrypterImpl decrypterImpl) {
        this.decrypterImpl = decrypterImpl;
    }
    
    @Override
    byte[] getContentEncryptionKey(CBORMap innerObject,
                                   ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                   CBORObject optionalKeyId) {
        // Mandatory algorithm
        KeyEncryptionAlgorithms keyEncryptionAlgorithm =
                KeyEncryptionAlgorithms.getAlgorithmFromId(
                        innerObject.get(ALGORITHM_LABEL).getInt());
 
        // Fetch public key if there is one
        PublicKey optionalPublicKey = null;
        if (innerObject.containsKey(PUBLIC_KEY_LABEL)) {
            optionalPublicKey = CBORPublicKey.convert(innerObject.get(PUBLIC_KEY_LABEL));
            // Please select ONE method for identifying the decryption key.
            CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
        }
        
        // Now we have what it takes for finding the proper private key
        PrivateKey privateKey = decrypterImpl.locate(optionalPublicKey,
                                                     optionalKeyId,
                                                     keyEncryptionAlgorithm,
                                                     contentEncryptionAlgorithm);

        // All algorithms but ECDH-EC depends on an encrypted key.
        byte[] optionalEncryptedKey = 
                CBORCryptoUtils.getEncryptedKey(innerObject, keyEncryptionAlgorithm);
        
        // All ECDH* algorithms depends on an ephemeral public key.
        PublicKey optionalEphemeralKey =
                CBORCryptoUtils.getEphemeralKey(innerObject, keyEncryptionAlgorithm);

        // Finally, get the decrypted key.
        return decrypterImpl.decrypt(privateKey,
                                     optionalEncryptedKey,
                                     optionalEphemeralKey,
                                     keyEncryptionAlgorithm, 
                                     contentEncryptionAlgorithm);
    }
}
