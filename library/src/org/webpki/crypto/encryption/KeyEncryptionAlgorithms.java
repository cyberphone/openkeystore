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
 * JWE and COSE key encryption algorithms.
 */
public enum KeyEncryptionAlgorithms {

    ECDH_ES_ALG_ID             ("ECDH-ES",              20,  true, false, false, -1),
    ECDH_ES_A128KW_ALG_ID      ("ECDH-ES+A128KW",       21,  true, false, true,  16),
    ECDH_ES_A192KW_ALG_ID      ("ECDH-ES+A192KW",       22,  true, false, true,  24),
    ECDH_ES_A256KW_ALG_ID      ("ECDH-ES+A256KW",       23,  true, false, true,  32),
    ECDH_ES_K256_ALG_ID        ("ECDH-ES-K256",        -25, false, false, false, -1),
    ECDH_ES_K256_A128KW_ALG_ID ("ECDH-ES-K256+A128KW", -29, false, false, true,  16),
    ECDH_ES_K256_A192KW_ALG_ID ("ECDH-ES-K256+A192KW", -30, false, false, true,  24),
    ECDH_ES_K256_A256KW_ALG_ID ("ECDH-ES-K256+A256KW", -31, false, false, true,  32),
    RSA_OAEP_ALG_ID            ("RSA-OAEP",            -40, false, true,  true,  -1),
    RSA_OAEP_256_ALG_ID        ("RSA-OAEP-256",        -41, false, true,  true,  -1);

    String joseName;
    int coseId;
    boolean concatKdf;  // false => HKDF-256
    boolean rsa;
    boolean keyWrap;
    int keyEncryptionKeyLength;

    KeyEncryptionAlgorithms(String joseName,
                            int coseId,
                            boolean concatKdf,
                            boolean rsa, 
                            boolean keyWrap, 
                            int keyEncryptionKeyLength) {
        this.joseName = joseName;
        this.coseId = coseId;
        this.concatKdf = concatKdf;
        this.rsa = rsa;
        this.keyWrap = keyWrap;
        this.keyEncryptionKeyLength = keyEncryptionKeyLength;
    }

    public boolean isRsa() {
        return rsa;
    }

    public boolean isKeyWrap() {
        return keyWrap;
    }

    public String getJoseAlgorithmId() {
        return joseName;
    }
    
    public int getCoseId() {
        return coseId;
    }
    
    public boolean usesConcatKdf() {
        return concatKdf;
    }

    public static KeyEncryptionAlgorithms getAlgorithmFromId(String algorithmId) throws IOException {
        for (KeyEncryptionAlgorithms algorithm : KeyEncryptionAlgorithms.values()) {
            if (algorithmId.equals(algorithm.joseName)) {
                return algorithm;
            }
        }
        throw new IOException("Unexpected algorithm: " + algorithmId);
    }
}
