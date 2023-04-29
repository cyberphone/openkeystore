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

import java.security.cert.X509Certificate;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for X.509 decryption.
 */
public class CBORX509Decrypter extends CBORDecrypter {
    
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
         *
         * @param certificatePath Certificate path in the encryption objectt
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Private decryption key.
         */
        PrivateKey locate(X509Certificate[] certificatePath,
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
     * Initializes a decrypter with a decrypter interface.
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
                        innerObject.get(ALGORITHM_LABEL).getInt());
 
        // Fetch certificate path
        X509Certificate[] certificatePath = CBORCryptoUtils.decodeCertificateArray(
                innerObject.get(CERT_PATH_LABEL).getArray());

        // Now we have what it takes for finding the proper private key
        PrivateKey privateKey = decrypterImpl.locate(certificatePath,
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
