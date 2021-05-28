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

import java.security.GeneralSecurityException;

/**
 * JWE and COSE key encryption algorithms.
 */
public enum KeyEncryptionAlgorithms {

    // Currently only defined by JOSE
    ECDH_ES              ("ECDH-ES",               20,  true, false, false, -1),
    ECDH_ES_A128KW       ("ECDH-ES+A128KW",        21,  true, false, true,  16),
    ECDH_ES_A192KW       ("ECDH-ES+A192KW",        22,  true, false, true,  24),
    ECDH_ES_A256KW       ("ECDH-ES+A256KW",        23,  true, false, true,  32),

    // Currently only defined by COSE
    ECDH_ES_HK256        ("ECDH-ES-HK256",        -25, false, false, false, -1),
    ECDH_ES_HK256_A128KW ("ECDH-ES-HK256+A128KW", -29, false, false, true,  16),
    ECDH_ES_HK256_A192KW ("ECDH-ES-HK256+A192KW", -30, false, false, true,  24),
    ECDH_ES_HK256_A256KW ("ECDH-ES-HK256+A256KW", -31, false, false, true,  32),

    // JOSE + COSE
    RSA_OAEP             ("RSA-OAEP",             -40, false, true,  true,  -1),
    RSA_OAEP_256         ("RSA-OAEP-256",         -41, false, true,  true,  -1);

    String joseId;
    int coseId;
    boolean concatKdf;  // false => HKDF-256
    boolean rsa;
    boolean keyWrap;
    int keyEncryptionKeyLength;

    KeyEncryptionAlgorithms(String joseId,
                            int coseId,
                            boolean concatKdf,
                            boolean rsa, 
                            boolean keyWrap, 
                            int keyEncryptionKeyLength) {
        this.joseId = joseId;
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
        return joseId;
    }
    
    public int getCoseAlgorithmId() {
        return coseId;
    }
    
    public boolean usesConcatKdf() {
        return concatKdf;
    }

    public static KeyEncryptionAlgorithms getAlgorithmFromId(String joseAlgorithmId) 
            throws GeneralSecurityException {
        for (KeyEncryptionAlgorithms algorithm : KeyEncryptionAlgorithms.values()) {
            if (joseAlgorithmId.equals(algorithm.joseId)) {
                return algorithm;
            }
        }
        throw new GeneralSecurityException("Unexpected algorithm: " + joseAlgorithmId);
    }

    public static KeyEncryptionAlgorithms getAlgorithmFromId(int coseAlgorithmId) 
            throws GeneralSecurityException {
        for (KeyEncryptionAlgorithms algorithm : KeyEncryptionAlgorithms.values()) {
            if (coseAlgorithmId == algorithm.coseId) {
                return algorithm;
            }
        }
        throw new GeneralSecurityException("Unexpected algorithm: " + coseAlgorithmId);
    }
}
