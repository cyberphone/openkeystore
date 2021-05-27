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
package org.webpki.crypto.encryption;

import java.io.IOException;

/**
 * JWE and COSE content encryption algorithms.
 */
public enum ContentEncryptionAlgorithms {

    A128CBC_HS256_ALG_ID ("A128CBC-HS256", 32, EncryptionCore.AES_CBC_IV_LENGTH, 
                          16,                                "HMACSHA256", false),
    A192CBC_HS384_ALG_ID ("A192CBC-HS384", 48, EncryptionCore.AES_CBC_IV_LENGTH, 
                          24,                                "HMACSHA384", false),
    A256CBC_HS512_ALG_ID ("A256CBC-HS512", 64, EncryptionCore.AES_CBC_IV_LENGTH,
                          32,                                "HMACSHA512", false),
    A128GCM_ALG_ID       ("A128GCM",       16, EncryptionCore.AES_GCM_IV_LENGTH,
                          EncryptionCore.AES_GCM_TAG_LENGTH,      null,         true),
    A192GCM_ALG_ID       ("A192GCM",       24, EncryptionCore.AES_GCM_IV_LENGTH,
                          EncryptionCore.AES_GCM_TAG_LENGTH,      null,         true),
    A256GCM_ALG_ID       ("A256GCM",       32, EncryptionCore.AES_GCM_IV_LENGTH,
                          EncryptionCore.AES_GCM_TAG_LENGTH,      null,         true);

    String joseName;
    int keyLength;
    int ivLength;
    int tagLength;
    String jceNameOfTagHmac;
    boolean gcm;

    ContentEncryptionAlgorithms(String joseName,
                                int keyLength,
                                int ivLength,
                                int tagLength,
                                String jceNameOfTagHmac, 
                                boolean gcm) {
        this.joseName = joseName;
        this.keyLength = keyLength;
        this.ivLength = ivLength;
        this.tagLength = tagLength;
        this.jceNameOfTagHmac = jceNameOfTagHmac;
        this.gcm = gcm;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public int getIvLength() {
        return ivLength;
    }

    public int getTagLength() {
        return tagLength;
    }
    
    public String getJoseAlgorithmId() {
        return joseName;
    }
    
    public static ContentEncryptionAlgorithms getAlgorithmFromId(String algorithmId) throws IOException {
        for (ContentEncryptionAlgorithms algorithm : ContentEncryptionAlgorithms.values()) {
            if (algorithmId.equals(algorithm.joseName)) {
                return algorithm;
            }
        }
        throw new IOException("Unexpected algorithm: " + algorithmId);
    }
}
