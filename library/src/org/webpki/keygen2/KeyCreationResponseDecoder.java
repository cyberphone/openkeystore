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
import java.util.LinkedHashMap;
import java.security.PublicKey;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationResponseDecoder extends KeyGen2Validator {

    private static final long serialVersionUID = 1L;

    LinkedHashMap<String, GeneratedPublicKey> generatedKeys = new LinkedHashMap<String, GeneratedPublicKey>();

    String clientSessionId;

    String serverSessionId;

    class GeneratedPublicKey {

        private GeneratedPublicKey() {}

        String id;

        PublicKey publicKey;

        byte[] attestation;
    }

    @Override
    protected void readJSONData(JSONObjectReader rd) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Session properties
        //////////////////////////////////////////////////////////////////////////
        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        clientSessionId = getID(rd, CLIENT_SESSION_ID_JSON);

        //////////////////////////////////////////////////////////////////////////
        // Get the generated keys [1..n]
        //////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader keyReader : getObjectArray(rd, GENERATED_KEYS_JSON)) {
            GeneratedPublicKey gk = new GeneratedPublicKey();
            gk.id = keyReader.getString(ID_JSON);
            gk.attestation = keyReader.getBinary(ATTESTATION_JSON);
            gk.publicKey = keyReader.getPublicKey(AlgorithmPreferences.JOSE_ACCEPT_PREFER);
            if (generatedKeys.put(gk.id, gk) != null) {
                ServerState.bad("Duplicate key id:" + gk.id);
            }
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.KEY_CREATION_RESPONSE.getName();
    }
}
