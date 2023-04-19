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

import org.webpki.crypto.ContentEncryptionAlgorithms;

/**
 * Class for symmetric key encryption.
 */
public class CBORSymKeyEncrypter extends CBOREncrypter {

    private byte[] contentEncryptionKey;
    
    /**
     * Initializes an encrypter object.
     * 
     * @param secretKey Encryption key
     * @param algorithm Encryption algorithm
     */
    public CBORSymKeyEncrypter(byte[] secretKey,
                               ContentEncryptionAlgorithms algorithm) {
        super(algorithm);
        contentEncryptionKey = secretKey;
    }

    @Override
    byte[] getContentEncryptionKey(CBORMap encryptionObject) {
        return contentEncryptionKey;
    }
}
