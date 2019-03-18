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
package org.webpki.keygen2;

import java.io.IOException;

import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningFinalizationResponseDecoder extends KeyGen2Validator {

    private static final long serialVersionUID = 1L;

    String clientSessionId;

    String serverSessionId;

    byte[] attestation;

    @Override
    protected void readJSONData(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Session properties
        /////////////////////////////////////////////////////////////////////////////////////////
        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        clientSessionId = getID(rd, CLIENT_SESSION_ID_JSON);

        attestation = rd.getBinary(ATTESTATION_JSON);
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.PROVISIONING_FINALIZATION_RESPONSE.getName();
    }
}
