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
package org.webpki.keygen2;

import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningFinalizationResponseEncoder extends JSONEncoder {

    String clientSessionId;

    String serverSessionId;

    byte[] attestation;

    // Constructors

    public ProvisioningFinalizationResponseEncoder(ProvisioningFinalizationRequestDecoder provisioningFinalizationRequestDecoder, 
                                                   byte[] attestation) {
        clientSessionId = provisioningFinalizationRequestDecoder.getClientSessionId();
        serverSessionId = provisioningFinalizationRequestDecoder.getServerSessionId();
        this.attestation = attestation;
    }

    @Override
    protected void writeJSONData(JSONObjectWriter wr) {
        //======================================================================//
        // Session properties
        //======================================================================//
        wr.setString(SERVER_SESSION_ID_JSON, serverSessionId);

        wr.setString(CLIENT_SESSION_ID_JSON, clientSessionId);

        wr.setBinary(ATTESTATION_JSON, attestation);
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.PROVISIONING_FINALIZATION_RESPONSE.getName();
    }

    @Override
    public String getContext() {
        return KEYGEN2_NS;
    }
}
