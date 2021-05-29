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
 * Class for creating CBOR symmetric key encryptions.
 * 
 * It uses COSE algorithms but not the packaging.
 *
 * Note that encrypters may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 */
public class CBORSymKeyEncrypter extends CBOREncrypter {

    /**
     * Initialize symmetric key encrypter.
     * 
     * @param secretKey The key to encrypt with
     * @param encryptionAlgorithm The algorithm to use
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public CBORSymKeyEncrypter(byte[] secretKey,
                               ContentEncryptionAlgorithms encryptionAlgorithm) 
            throws IOException, GeneralSecurityException {
        super(encryptionAlgorithm);
        contentEncryptionKey = secretKey;
    }
}
