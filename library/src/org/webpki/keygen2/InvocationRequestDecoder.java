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
import java.util.LinkedHashSet;
import java.util.Set;

import org.webpki.crypto.KeyContainerTypes;

import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class InvocationRequestDecoder extends ClientDecoder {

    private static final long serialVersionUID = 1L;

    enum CAPABILITY {UNDEFINED, URI_FEATURE, VALUES, IMAGE_ATTRIBUTES}

    LinkedHashMap<String, CAPABILITY> queriedCapabilities = new LinkedHashMap<String, CAPABILITY>();

    Action action;

    public Action getAction() {
        return action;
    }


    boolean privacyEnabled;

    public boolean getPrivacyEnabledFlag() {
        return privacyEnabled;
    }


    public Set<String> getQueriedCapabilities() {
        return queriedCapabilities.keySet();
    }


    String serverSessionId;

    public String getServerSessionId() {
        return serverSessionId;
    }


    String[] languages; // Optional

    public String[] getOptionalLanguageList() {
        return languages;
    }


    String cancelUrl;

    public String getOptionalCancelUrl() {
        return cancelUrl;
    }


    LinkedHashSet<KeyContainerTypes> keyContainerList;  // Optional
    
    public LinkedHashSet<KeyContainerTypes> getOptionalKeyContainerList() {
        return keyContainerList;
    }


    @Override
    void readServerRequest(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Session properties
        /////////////////////////////////////////////////////////////////////////////////////////
        action = Action.getActionFromString(rd.getString(ACTION_JSON));

        languages = rd.getStringArrayConditional(PREFERREDD_LANGUAGES_JSON);

        keyContainerList = KeyContainerTypes.getOptionalKeyContainerSet(rd.getStringArrayConditional(KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS));

        privacyEnabled = rd.getBooleanConditional(PRIVACY_ENABLED_JSON);

        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        cancelUrl = rd.getStringConditional(CANCEL_URL_JSON);

        String[] capabilityUris = KeyGen2Validator.getURIListConditional(rd, CLIENT_CAPABILITY_QUERY_JSON);
        if (capabilityUris != null) {
            for (String uri : capabilityUris) {
                if (queriedCapabilities.put(uri, CAPABILITY.UNDEFINED) != null) {
                    KeyGen2Validator.bad("Duplicate capability URI: " + uri);
                }
            }
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.INVOCATION_REQUEST.getName();
    }
}
