/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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

import org.webpki.crypto.KeyContainerTypes;

import org.webpki.json.JSONObjectWriter;

import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class InvocationRequestEncoder extends ServerEncoder {

    private static final long serialVersionUID = 1L;

    Action action = Action.MANAGE;

    private ServerState serverState;

    // Constructor

    public InvocationRequestEncoder(ServerState serverState) throws IOException {
        serverState.checkState(true, ProtocolPhase.INVOCATION);
        this.serverState = serverState;
    }

    public void setAction(Action action) {
        this.action = action;
    }

    @Override
    void writeServerRequest(JSONObjectWriter wr) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, serverState.serverSessionId);

        wr.setString(ACTION_JSON, action.getJSONName());

        if (serverState.privacyEnabledSet) {
            wr.setBoolean(PRIVACY_ENABLED_JSON, serverState.privacyEnabled);
        }

        setOptionalStringArray(wr, PREFERREDD_LANGUAGES_JSON, serverState.languageList);

        setOptionalStringArray(wr, KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS, serverState.keyContainerList);

        setOptionalStringArray(wr,
                               CLIENT_CAPABILITY_QUERY_JSON,
                               serverState.queriedCapabilities.isEmpty() ?
                                   null : serverState.queriedCapabilities.keySet().toArray(new String[0]));
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.INVOCATION_REQUEST.getName();
    }
}
