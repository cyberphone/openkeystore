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

import org.webpki.crypto.ContentEncryptionAlgorithms;

/**
 * Class for symmetric key encryption.
 */
public class CBORSymKeyEncrypter extends CBOREncrypter<CBORSymKeyEncrypter> {

    private byte[] contentEncryptionKey;
    
    /**
     * Creates an encrypter object with a secret key.
     * 
     * @param secretKey Encryption key
     * @param algorithm Encryption algorithm
     */
    public CBORSymKeyEncrypter(byte[] secretKey, ContentEncryptionAlgorithms algorithm) {
        super(algorithm);
        contentEncryptionKey = secretKey;
    }

    @Override
    byte[] getContentEncryptionKey(CBORMap encryptionObject) {
        return contentEncryptionKey;
    }

    @Override
    CBORSymKeyEncrypter getThis() {
        return this;
    }
}
