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

import java.util.ArrayList;

import java.security.PublicKey;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationResponseEncoder extends JSONEncoder {

    String clientSessionId;

    String serverSessionId;

    ArrayList<GeneratedPublicKey> generatedKeys = new ArrayList<>();

    private class GeneratedPublicKey {
        String id;

        PublicKey publicKey;

        byte[] attestation;

        GeneratedPublicKey(String id) {
            this.id = id;
            generatedKeys.add(this);
        }

    }


    public void addPublicKey(PublicKey publicKey, byte[] attestation, String id) {
        GeneratedPublicKey gk = new GeneratedPublicKey(id);
        gk.publicKey = publicKey;
        gk.attestation = attestation;
    }


    public KeyCreationResponseEncoder(KeyCreationRequestDecoder keyCreationRequestDecoder) {
        clientSessionId = keyCreationRequestDecoder.getClientSessionId();
        serverSessionId = keyCreationRequestDecoder.getServerSessionId();
    }


    @Override
    protected void writeJSONData(JSONObjectWriter wr) {
        //======================================================================//
        // Session properties
        //======================================================================//
        wr.setString(SERVER_SESSION_ID_JSON, serverSessionId);

        wr.setString(CLIENT_SESSION_ID_JSON, clientSessionId);

        //======================================================================//
        // The generated keys
        //======================================================================//
        JSONArrayWriter keys = wr.setArray(GENERATED_KEYS_JSON);
        for (GeneratedPublicKey gk : generatedKeys) {
            keys.setObject()
                .setString(ID_JSON, gk.id)
                .setPublicKey(gk.publicKey, AlgorithmPreferences.JOSE_ACCEPT_PREFER)
                .setBinary(ATTESTATION_JSON, gk.attestation);
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.KEY_CREATION_RESPONSE.getName();
    }

    @Override
    public String getContext() {
        return KEYGEN2_NS;
    }
}
