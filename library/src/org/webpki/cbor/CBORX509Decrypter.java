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

import java.security.cert.X509Certificate;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.EncryptionCore;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for X.509 decryption.
 */
public class CBORX509Decrypter extends CBORDecrypter<CBORX509Decrypter> {
    
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
         *
         * @param certificatePath Certificate path in the encryption object
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Private decryption key.
         */
        PrivateKey locate(X509Certificate[] certificatePath,
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
         * @param certificatePath Certificate path in the encryption object
         * @param optionalEncryptedKey Optional encrypted key
         * @param optionalEphemeralKey Optional ephemeral key
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Decrypted key.
         */
        byte[] decrypt(X509Certificate[] certificatePath, 
                       byte[] optionalEncryptedKey,
                       PublicKey optionalEphemeralKey,
                       KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                       ContentEncryptionAlgorithms contentEncryptionAlgorithm);

    }

    KeyLocator keyLocator;
    
    DecrypterImpl decrypterImpl;
    
    /**
     * Creates a decrypter object with a key locator interface.
     * <p>
     * Uses the Java crypto provider system.
     * </p>
     * 
     * @param keyLocator Key locator implementation
     */
    public CBORX509Decrypter(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }

    /**
     * Creates a decrypter object with a decrypter interface.
     * 
     * @param decrypterImpl Decrypter implementation
     */
    public CBORX509Decrypter(DecrypterImpl decrypterImpl) {
        this.decrypterImpl = decrypterImpl;
    }
    
    @Override
    byte[] getContentEncryptionKey(CBORMap innerObject,
                                   ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                   CBORObject optionalKeyId) {
        // keyId and certificates? Never!
        CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);

        // Mandatory algorithm
        KeyEncryptionAlgorithms keyEncryptionAlgorithm =
                KeyEncryptionAlgorithms.getAlgorithmFromId(
                        innerObject.get(ALGORITHM_LABEL).getInt32());
 
        // Fetch certificate path
        X509Certificate[] certificatePath = CBORCryptoUtils.decodeCertificateArray(
                innerObject.get(CERT_PATH_LABEL).getArray());

        // All algorithms but ECDH-EC depends on an encrypted key.
        byte[] optionalEncryptedKey = 
                CBORCryptoUtils.getEncryptedKey(innerObject, keyEncryptionAlgorithm);
        
        // All ECDH* algorithms depends on an ephemeral public key.
        PublicKey optionalEphemeralKey =
                CBORCryptoUtils.getEphemeralKey(innerObject, keyEncryptionAlgorithm);

        // Finally, get the decrypted key.
        return decrypterImpl == null ?
 
            // Internal crypto mode.
            EncryptionCore.decryptKey(true, 
                                      keyLocator.locate(certificatePath,
                                                        keyEncryptionAlgorithm,
                                                        contentEncryptionAlgorithm), 
                                                        optionalEncryptedKey, 
                                                        optionalEphemeralKey, 
                                                        keyEncryptionAlgorithm, 
                                                        contentEncryptionAlgorithm)
                                     :
            // External crypto mode.
            decrypterImpl.decrypt(certificatePath, 
                                  optionalEncryptedKey,
                                  optionalEphemeralKey,
                                  keyEncryptionAlgorithm, 
                                  contentEncryptionAlgorithm);
    }

    @Override
    CBORX509Decrypter getThis() {
        return this;
    }
}
