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
package org.webpki.json;

import java.io.IOException;

/**
 * JWE algorithms.
 */
public enum KeyEncryptionAlgorithms {

    JOSE_ECDH_ES_ALG_ID        ("ECDH-ES",        false, false, -1),
    JOSE_ECDH_ES_A128KW_ALG_ID ("ECDH-ES+A128KW", false, true,  16),
    JOSE_ECDH_ES_A192KW_ALG_ID ("ECDH-ES+A192KW", false, true,  24),
    JOSE_ECDH_ES_A256KW_ALG_ID ("ECDH-ES+A256KW", false, true,  32),
    JOSE_RSA_OAEP_ALG_ID       ("RSA-OAEP",       true,  true,  -1),
    JOSE_RSA_OAEP_256_ALG_ID   ("RSA-OAEP-256",   true,  true,  -1);

    String joseName;
    boolean rsa;
    boolean keyWrap;
    int keyEncryptionKeyLength;

    KeyEncryptionAlgorithms(String joseName, boolean rsa, boolean keyWrap, int keyEncryptionKeyLength) {
        this.joseName = joseName;
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

    @Override
    public String toString() {
        return joseName;
    }

    public static KeyEncryptionAlgorithms getAlgorithmFromId(String algorithmId) throws IOException {
        for (KeyEncryptionAlgorithms algorithm : KeyEncryptionAlgorithms.values()) {
            if (algorithmId.equals(algorithm.joseName)) {
                return algorithm;
            }
        }
        throw new IOException("Unexpected argument to \"" + JSONCryptoHelper.ALGORITHM_JSON + "\": " + algorithmId);
    }
}
