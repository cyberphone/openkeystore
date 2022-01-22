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

import org.webpki.crypto.encryption.ContentEncryptionAlgorithms;

/**
 * Class for CBOR symmetric key decryption.
 * 
 * It uses COSE algorithms but relies on CEF for the packaging.
 *
 * Note that decrypter objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe. 
 */
public class CBORSymKeyDecrypter extends CBORDecrypter {
    
    /**
     * For dynamic key retrieval.
     */
    public interface KeyLocator {


        /**
         * Lookup of secret decryption key.
         * 
         * This interface also enables encryption parameter validation.
         * 
         * @param optionalKeyId Optional key Id found in the encryption object
         * @param contentEncryptionAlgorithm The requested content encryption algorithm
         * @return Secret key
         * @throws IOException
         * @throws GeneralSecurityException
         */
        byte[] locate(CBORObject optionalKeyId, 
                      ContentEncryptionAlgorithms contentEncryptionAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    KeyLocator keyLocator;
    
    /**
     * Initializes a decrypter with a secret key.
     * 
     * @param secretKey The anticipated secret key to decrypt with
     */
    public CBORSymKeyDecrypter(byte[] secretKey) {
        this(new KeyLocator() {

            @Override
            public byte[] locate(CBORObject optionalKeyId,
                                 ContentEncryptionAlgorithms contentEncryptionAlgorithm)
                    throws IOException, GeneralSecurityException {
                return secretKey;
            }
            
        });
    }

    /**
     * Initializes a decrypter with a key locator.
     * 
     * @param keyLocator The call back
     */
    public CBORSymKeyDecrypter(KeyLocator keyLocator) {
        this.keyLocator = keyLocator;
    }
    
    @Override
    byte[] getContentEncryptionKey(CBORMap innerObject,
                                   ContentEncryptionAlgorithms contentEncryptionAlgorithm,
                                   CBORObject optionalKeyId) throws IOException,
                                                                     GeneralSecurityException {
        return keyLocator.locate(optionalKeyId, contentEncryptionAlgorithm);
    }
}
