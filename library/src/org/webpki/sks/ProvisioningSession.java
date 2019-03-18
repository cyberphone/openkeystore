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

import java.security.interfaces.ECPublicKey;

public class ProvisioningSession {

    int provisioningHandle;

    public int getProvisioningHandle() {
        return provisioningHandle;
    }

    String clientSessionId;

    public String getClientSessionId() {
        return clientSessionId;
    }

    byte[] attestation;

    public byte[] getAttestation() {
        return attestation;
    }

    ECPublicKey clientEphemeralKey;

    public ECPublicKey getClientEphemeralKey() {
        return clientEphemeralKey;
    }

    public ProvisioningSession(int provisioningHandle,
                               String clientSessionId,
                               byte[] attestation,
                               ECPublicKey clientEphemeralKey) {
        this.provisioningHandle = provisioningHandle;
        this.clientSessionId = clientSessionId;
        this.attestation = attestation;
        this.clientEphemeralKey = clientEphemeralKey;
    }

}
