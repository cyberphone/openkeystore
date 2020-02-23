/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

import java.io.IOException;

/**
 * Initiator object for symmetric key encryptions.
 */
public class JSONSymKeyEncrypter extends JSONEncrypter {

    private static final long serialVersionUID = 1L;

     /**
     * Constructor for JCE based solutions.
     * @param contentEncryptionKey Symmetric key
     * @throws IOException &nbsp;
     */
    public JSONSymKeyEncrypter(byte[] contentEncryptionKey) throws IOException {
        this.contentEncryptionKey = contentEncryptionKey;
        this.keyEncryptionAlgorithm = null;
    }

    @Override
    void writeKeyData(JSONObjectWriter wr) throws IOException {
    }
}
