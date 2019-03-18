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

import java.util.Iterator;

import org.webpki.sks.SecureKeyStore;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

import org.webpki.keygen2.ServerState.PINPolicy;
import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationRequestEncoder extends ServerEncoder {

    private static final long serialVersionUID = 1L;

    boolean deferredIssuance;

    ServerState serverState;

    private String algorithm = SecureKeyStore.ALGORITHM_KEY_ATTEST_1;


    // Constructors

    public KeyCreationRequestEncoder(ServerState serverState) throws IOException {
        this.serverState = serverState;
        serverState.checkState(true, serverState.currentPhase == ProtocolPhase.CREDENTIAL_DISCOVERY ? ProtocolPhase.CREDENTIAL_DISCOVERY : ProtocolPhase.KEY_CREATION);
        serverState.currentPhase = ProtocolPhase.KEY_CREATION;
    }


    public void setDeferredIssuance(boolean flag) {
        deferredIssuance = flag;
    }


    public void setKeyAttestationAlgorithm(String keyAttestationAlgorithmUri) {
        this.algorithm = keyAttestationAlgorithmUri;
    }


    void writeKeys(JSONObjectWriter wr, PINPolicy pinPolicy) throws IOException {
        JSONArrayWriter keys = null;
        for (ServerState.Key requestedKey : serverState.requestedKeys.values()) {
            if (requestedKey.pinPolicy == pinPolicy) {
                if (keys == null) {
                    keys = wr.setArray(KEY_ENTRY_SPECIFIERS_JSON);
                }
                requestedKey.writeRequest(keys.setObject());
            }
        }
    }

    @Override
    void writeServerRequest(JSONObjectWriter wr) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, serverState.serverSessionId);

        wr.setString(CLIENT_SESSION_ID_JSON, serverState.clientSessionId);

        wr.setString(KEY_ENTRY_ALGORITHM_JSON, algorithm);

        if (deferredIssuance) {
            wr.setBoolean(DEFERRED_ISSUANCE_JSON, deferredIssuance);
        }

        serverState.keyAttestationAlgorithm = algorithm;

        ////////////////////////////////////////////////////////////////////////
        // There MUST not be zero keys to initialize...
        ////////////////////////////////////////////////////////////////////////
        if (serverState.requestedKeys.isEmpty()) {
            bad("Empty request not allowd!");
        }
        if (!serverState.pukPolicies.isEmpty()) {
            JSONArrayWriter puk = wr.setArray(PUK_POLICY_SPECIFIERS_JSON);
            for (ServerState.PUKPolicy pukPolicy : serverState.pukPolicies) {
                JSONObjectWriter pukWriter = puk.setObject();
                pukPolicy.writePolicy(pukWriter);
                JSONArrayWriter pin = pukWriter.setArray(PIN_POLICY_SPECIFIERS_JSON);
                Iterator<ServerState.PINPolicy> pin_policies = serverState.pinPolicies.iterator();
                while (pin_policies.hasNext()) {
                    ServerState.PINPolicy pinPolicy = pin_policies.next();
                    JSONObjectWriter pinWriter = pin.setObject();
                    pinPolicy.writePolicy(pinWriter);
                    pin_policies.remove();
                    writeKeys(pinWriter, pinPolicy);
                }
            }
        }
        if (!serverState.pinPolicies.isEmpty()) {
            JSONArrayWriter pin = wr.setArray(PIN_POLICY_SPECIFIERS_JSON);
            for (ServerState.PINPolicy pinPolicy : serverState.pinPolicies) {
                JSONObjectWriter pinWriter = pin.setObject();
                pinPolicy.writePolicy(pinWriter);
                writeKeys(pinWriter, pinPolicy);
            }
        }
        writeKeys(wr, null);
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.KEY_CREATION_REQUEST.getName();
    }
}
