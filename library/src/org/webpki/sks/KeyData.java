/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
package org.webpki.sks;

import java.security.PublicKey;

public class KeyData {

    private int keyHandle;

    private PublicKey publicKey;

    private byte[] attestation;

    public KeyData(int keyHandle,
                   PublicKey publicKey,
                   byte[] attestation) {
        this.keyHandle = keyHandle;
        this.publicKey = publicKey;
        this.attestation = attestation;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public int getKeyHandle() {
        return keyHandle;
    }

    public byte[] getAttestation() {
        return attestation;
    }

}
