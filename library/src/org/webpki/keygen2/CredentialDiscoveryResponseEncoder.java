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

import java.util.LinkedHashMap;
import java.util.ArrayList;

import java.security.cert.X509Certificate;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryResponseEncoder extends JSONEncoder {

    class MatchingCredential {

        X509Certificate[] certificatePath;

        String clientSessionId;

        String serverSessionId;

        boolean locked;
    }

    public class LookupResult {

        String id;

        ArrayList<MatchingCredential> matchingCredentials = new ArrayList<>();

        LookupResult(String id) {
            this.id = id;
        }

        public void addMatchingCredential(X509Certificate[] certificatePath, 
                                          String clientSessionId,
                                          String serverSessionId,
                                          boolean locked) {
            MatchingCredential matchingCredential = new MatchingCredential();
            matchingCredential.certificatePath = certificatePath;
            matchingCredential.clientSessionId = clientSessionId;
            matchingCredential.serverSessionId = serverSessionId;
            matchingCredential.locked = locked;
            matchingCredentials.add(matchingCredential);
        }
    }


    ArrayList<LookupResult> lookupResults = new ArrayList<>();

    LinkedHashMap<String, CredentialDiscoveryRequestDecoder.LookupSpecifier> ref;

    String clientSessionId;

    String serverSessionId;


    // Constructors

    public CredentialDiscoveryResponseEncoder(CredentialDiscoveryRequestDecoder credentialDiscoveryRequestDecoder) {
        serverSessionId = credentialDiscoveryRequestDecoder.serverSessionId;
        clientSessionId = credentialDiscoveryRequestDecoder.clientSessionId;
        this.ref = credentialDiscoveryRequestDecoder.lookupSpecifiers;
    }


    public LookupResult addLookupResult(String id) {
        LookupResult lookupResult = new LookupResult(id);
        if (!ref.containsKey(id)) {
            throw new KeyGen2Exception("Non-matching \"ID\": " + id);
        }
        lookupResults.add(lookupResult);
        return lookupResult;
    }


    @Override
    protected void writeJSONData(JSONObjectWriter wr) {
        //////////////////////////////////////////////////////////////////////////
        // Session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, serverSessionId);

        wr.setString(CLIENT_SESSION_ID_JSON, clientSessionId);

        ////////////////////////////////////////////////////////////////////////
        // Lookup results
        ////////////////////////////////////////////////////////////////////////
        if (lookupResults.isEmpty()) {
            throw new KeyGen2Exception("There must be at least one result defined");
        }
        if (lookupResults.size() != ref.size()) {
            throw new KeyGen2Exception("Missing outputed results");
        }
        JSONArrayWriter lookups = wr.setArray(LOOKUP_RESULTS_JSON);
        for (LookupResult lookupResult : lookupResults) {
            JSONObjectWriter lookupWriter = lookups.setObject();
            lookupWriter.setString(ID_JSON, lookupResult.id);
            JSONArrayWriter matcherArray = lookupWriter.setArray(MATCHING_CREDENTIALS_JSON);
            for (MatchingCredential matchingCredential : lookupResult.matchingCredentials) {
                JSONObjectWriter matchObject = matcherArray.setObject();
                matchObject.setString(SERVER_SESSION_ID_JSON, matchingCredential.serverSessionId);
                matchObject.setString(CLIENT_SESSION_ID_JSON, matchingCredential.clientSessionId);
                matchObject.setCertificatePath(matchingCredential.certificatePath);
                if (matchingCredential.locked) {
                    matchObject.setBoolean(LOCKED_JSON, matchingCredential.locked);
                }
            }
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.CREDENTIAL_DISCOVERY_RESPONSE.getName();
    }

    @Override
    public String getContext() {
        return KEYGEN2_NS;
    }
}
