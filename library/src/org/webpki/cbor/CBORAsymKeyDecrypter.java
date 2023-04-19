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

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for asymmetric key decryption.
 */
public class CBORAsymKeyDecrypter extends CBORDecrypter {
    
    /**
     * Interface for dynamic key retrieval.
     */
    public interface KeyLocator {

        /**
         * Lookup of private decryption key.

         * This interface also enables encryption parameter verification.
         * 
         * @param optionalPublicKey Optional public key found in the encryption object
         * @param optionalKeyId Optional key Id found in the encryption object
         * @param keyEncryptionAlgorithm The requested key encryption algorithm
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Decryption key
         * @throws IOException
         * @throws GeneralSecurityException
         */
        PrivateKey locate(PublicKey optionalPublicKey, 
                          CBORObject optionalKeyId,
                          KeyEncryptionAlgorithms keyEncryptionAlgorithm,
                          ContentEncryptionAlgorithms contentEncryptionAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    KeyLocator keyLocator;
    
    /**
     * Initializes a decrypter with a private key.
     * <p>
     * This constructor presumes that the decryption key is given by the context.
     * </p>
     * @param privateKey Decryption key
     */
    public CBORAsymKeyDecrypter(PrivateKey privateKey) {
        this((optionalPublicKey, 
              optionalKeyId, 
              keyEncryptionAlgorithm, 
              contentEncryptionAlgorithm) -> privateKey);
    }

    /**
     * Initializes a decrypter with a key locator.
     * 
     * @param keyLocator KeyLocator implementation
     */
    public CBORAsymKeyDecrypter(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }
    
    @Override
    byte[] getContentEncryptionKey(CBORMap innerObject,
                                   ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                   CBORObject optionalKeyId) throws IOException,
                                                                    GeneralSecurityException {
        // Mandatory algorithm
        KeyEncryptionAlgorithms keyEncryptionAlgorithm =
                KeyEncryptionAlgorithms.getAlgorithmFromId(
                        innerObject.getObject(ALGORITHM_LABEL).getInt());
 
        // Fetch public key if there is one
        PublicKey optionalPublicKey = null;
        if (innerObject.hasKey(PUBLIC_KEY_LABEL)) {
            optionalPublicKey = CBORPublicKey.convert(innerObject.getObject(PUBLIC_KEY_LABEL));
            // Please select ONE method for identifying the decryption key.
            CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
        }

        // Now we have what it takes for finding the proper private key
        PrivateKey privateKey = keyLocator.locate(optionalPublicKey,
                                                  optionalKeyId,
                                                  keyEncryptionAlgorithm,
                                                  contentEncryptionAlgorithm);
        return CBORCryptoUtils.asymKeyDecrypt(privateKey,
                                              innerObject,
                                              keyEncryptionAlgorithm,
                                              contentEncryptionAlgorithm); 
    }
}
