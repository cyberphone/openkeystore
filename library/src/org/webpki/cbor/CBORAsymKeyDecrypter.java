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
public class CBORAsymKeyDecrypter extends CBORDecrypter<CBORAsymKeyDecrypter> {
    
    /**
     * Decrypter private key locator.
     */
    public interface KeyLocator {

        /**
         * Locate private decryption key.
         * <p>
         * Uses the Java crypto provider system.
         * </p>
         * <p>
         * Implementations <b>must</b> throw {@link org.webpki.crypto.CryptoException} for
         * errors related to cryptography and security.
         * </p>
         *<p>
         * This interface also enables encryption parameter verification.
         * </p>
         * 
         * @param optionalPublicKey Defined it provided in the CEF object
         * @param optionalKeyId Defined it provided in the CEF object
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Private decryption key.
         */
        PrivateKey locate(PublicKey optionalPublicKey, 
                          CBORObject optionalKeyId,
                          KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                          ContentEncryptionAlgorithms contentEncryptionAlgorithm);

    }

    /**
     * Decrypter engine implementation interface.
     */
    public interface DecrypterImpl {
 
        /**
         * Decrypt encrypted key.
         * <p>
         * This interface assumes that the private key resides in an external
         * hardware or software solution.  The private key is either implicit
         * or located by the <code>optionalPublicKey</code> or
         * <code>optionalKeyId</code> parameters. 
         * </p>
         * <p>
         * Implementations <b>must</b> throw {@link org.webpki.crypto.CryptoException} for
         * errors related to cryptography and security.
         * </p>
         * 
         * @param optionalPublicKey Defined it provided in the CEF object
         * @param optionalKeyId Defined if provided in the CEF object
         * @param optionalEncryptedKey Optional encrypted key (algorithm dependent)
         * @param optionalEphemeralKey Optional ephemeral key (algorithm dependent)
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Decrypted key.
         */
        byte[] decrypt(PublicKey optionalPublicKey,
                       CBORObject optionalKeyId,
                       byte[] optionalEncryptedKey,
                       PublicKey optionalEphemeralKey,
                       KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                       ContentEncryptionAlgorithms contentEncryptionAlgorithm);

    }
    
    KeyLocator keyLocator;

    DecrypterImpl decrypterImpl;
    
    /**
     * Creates a decrypter object with a private key.
     * <p>
     * Uses the Java crypto provider system.
     * </p>
     * <p>
     * This constructor presumes that the decryption key is given by the context.
     * </p>
     * @param privateKey Decryption key
     */
    public CBORAsymKeyDecrypter(PrivateKey privateKey) {
        this(new KeyLocator() {

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
     * Creates a decrypter object with a key locator interface.
     * <p>
     * Uses the Java crypto provider system.
     * </p>
     * 
     * @param keyLocator Key locator implementation
     */
    public CBORAsymKeyDecrypter(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }

    /**
     * Creates a decrypter object with a decrypter interface.
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
                        innerObject.get(CXF_ALGORITHM_LBL).getInt32());
 
        // Fetch public key if there is one
        PublicKey optionalPublicKey = null;
        if (innerObject.containsKey(CXF_PUBLIC_KEY_LBL)) {
            optionalPublicKey = CBORPublicKey.convert(innerObject.get(CXF_PUBLIC_KEY_LBL));
            // Please select ONE method for identifying the decryption key.
            CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
        }

        // All algorithms but ECDH-EC depends on an encrypted key.
        byte[] optionalEncryptedKey = 
                CBORCryptoUtils.getEncryptedKey(innerObject, keyEncryptionAlgorithm);
        
        // All ECDH* algorithms depends on an ephemeral public key.
        PublicKey optionalEphemeralKey =
                CBORCryptoUtils.getEphemeralKey(innerObject, keyEncryptionAlgorithm);

        // Finally, get the decrypted key.
        return decrypterImpl == null ?
            // Using internal crypto.
            EncryptionCore.decryptKey(true,
                                      keyLocator.locate(optionalPublicKey,
                                                        optionalKeyId,
                                                        keyEncryptionAlgorithm,
                                                        contentEncryptionAlgorithm), 
                                      optionalEncryptedKey, 
                                      optionalEphemeralKey, 
                                      keyEncryptionAlgorithm, 
                                      contentEncryptionAlgorithm)
                                     :
            // Using external crypto.
            decrypterImpl.decrypt(optionalPublicKey,
                                  optionalKeyId,
                                  optionalEncryptedKey,
                                  optionalEphemeralKey,
                                  keyEncryptionAlgorithm, 
                                  contentEncryptionAlgorithm);
    }

    @Override
    CBORAsymKeyDecrypter getThis() {
        return this;
    }
}
