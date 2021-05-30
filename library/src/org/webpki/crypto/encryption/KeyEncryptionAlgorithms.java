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
 * JWE and COSE key encryption algorithms.
 * 
 * Note that JOSE and COSE use different KDFs.
 */
public enum KeyEncryptionAlgorithms {

    // ECDH
    ECDH_ES        ("ECDH-ES",        -25, false, false, -1),
    ECDH_ES_A128KW ("ECDH-ES+A128KW", -29, false, true,  16),
    ECDH_ES_A192KW ("ECDH-ES+A192KW", -30, false, true,  24),
    ECDH_ES_A256KW ("ECDH-ES+A256KW", -31, false, true,  32),

    // RSA
    RSA_OAEP       ("RSA-OAEP",       -40,  true, true,  -1),
    RSA_OAEP_256   ("RSA-OAEP-256",   -41,  true, true,  -1);

    String joseId;
    int coseId;
    boolean rsa;
    boolean keyWrap;
    int keyEncryptionKeyLength;

    KeyEncryptionAlgorithms(String joseId,
                            int coseId,
                            boolean rsa, 
                            boolean keyWrap, 
                            int keyEncryptionKeyLength) {
        this.joseId = joseId;
        this.coseId = coseId;
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
        return joseId;
    }
    
    public int getCoseAlgorithmId() {
        return coseId;
    }
    
    public static KeyEncryptionAlgorithms getAlgorithmFromId(String joseAlgorithmId) {
        for (KeyEncryptionAlgorithms algorithm : KeyEncryptionAlgorithms.values()) {
            if (joseAlgorithmId.equals(algorithm.joseId)) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unexpected algorithm: " + joseAlgorithmId);
    }

    public static KeyEncryptionAlgorithms getAlgorithmFromId(int coseAlgorithmId) {
        for (KeyEncryptionAlgorithms algorithm : KeyEncryptionAlgorithms.values()) {
            if (coseAlgorithmId == algorithm.coseId) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unexpected algorithm: " + coseAlgorithmId);
    }
}
