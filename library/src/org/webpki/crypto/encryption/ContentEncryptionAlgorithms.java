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

/**
 * JWE and COSE content encryption algorithms.
 */
public enum ContentEncryptionAlgorithms {

    // Currently only defined by JOSE
    A128CBC_HS256 ("A128CBC-HS256", 200, 32, EncryptionCore.AES_CBC_IV_LENGTH, 
                   16,                         "HMACSHA256", false),
    A192CBC_HS384 ("A192CBC-HS384", 201, 48, EncryptionCore.AES_CBC_IV_LENGTH, 
                   24,                         "HMACSHA384", false),
    A256CBC_HS512 ("A256CBC-HS512", 202, 64, EncryptionCore.AES_CBC_IV_LENGTH,
                   32,                         "HMACSHA512", false),

    // JOSE + COSE
    A128GCM       ("A128GCM",         1, 16, EncryptionCore.AES_GCM_IV_LENGTH,
                   EncryptionCore.AES_GCM_TAG_LENGTH,      null,         true),
    A192GCM       ("A192GCM",         2, 24, EncryptionCore.AES_GCM_IV_LENGTH,
                   EncryptionCore.AES_GCM_TAG_LENGTH,      null,         true),
    A256GCM       ("A256GCM",         3, 32, EncryptionCore.AES_GCM_IV_LENGTH,
                   EncryptionCore.AES_GCM_TAG_LENGTH,      null,         true);

    String joseId;
    int coseId;
    int keyLength;
    int ivLength;
    int tagLength;
    String jceNameOfTagHmac;
    boolean gcm;

    ContentEncryptionAlgorithms(String joseId,
                                int coseId,
                                int keyLength,
                                int ivLength,
                                int tagLength,
                                String jceNameOfTagHmac, 
                                boolean gcm) {
        this.joseId = joseId;
        this.coseId = coseId;
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
        return joseId;
    }
    
    public int getCoseAlgorithmId() {
        return coseId;
    }
    
    public static ContentEncryptionAlgorithms getAlgorithmFromId(String joseAlgorithmId) {
        for (ContentEncryptionAlgorithms algorithm : ContentEncryptionAlgorithms.values()) {
            if (joseAlgorithmId.equals(algorithm.joseId)) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unexpected algorithm: " + joseAlgorithmId);
    }

    public static ContentEncryptionAlgorithms getAlgorithmFromId(int coseAlgorithmId) {
        for (ContentEncryptionAlgorithms algorithm : ContentEncryptionAlgorithms.values()) {
            if (coseAlgorithmId == algorithm.coseId) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unexpected algorithm: " + coseAlgorithmId);
    }
}

