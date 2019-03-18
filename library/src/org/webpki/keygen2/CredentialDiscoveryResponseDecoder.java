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

import java.security.cert.X509Certificate;

import java.util.Vector;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryResponseDecoder extends KeyGen2Validator {

    private static final long serialVersionUID = 1L;

    public class MatchingCredential {

        MatchingCredential() {}

        X509Certificate[] certificatePath;

        String clientSessionId;

        String serverSessionId;

        boolean locked;

        public String getClientSessionId() {
            return clientSessionId;
        }

        public String getServerSessionId() {
            return serverSessionId;
        }

        public X509Certificate[] getCertificatePath() {
            return certificatePath;
        }

        public boolean isLocked() {
            return locked;
        }
    }

    public class LookupResult {

        String id;

        LookupResult() {}

        Vector<MatchingCredential> matchingCredentials = new Vector<MatchingCredential>();

        LookupResult(JSONObjectReader rd) throws IOException {
            id = KeyGen2Validator.getID(rd, ID_JSON);
            JSONArrayReader matches = rd.getArray(MATCHING_CREDENTIALS_JSON);
            while (matches.hasMore()) {
                JSONObjectReader matchObject = matches.getObject();
                MatchingCredential matchingCredential = new MatchingCredential();
                matchingCredential.clientSessionId = KeyGen2Validator.getID(matchObject, CLIENT_SESSION_ID_JSON);
                matchingCredential.serverSessionId = KeyGen2Validator.getID(matchObject, SERVER_SESSION_ID_JSON);
                matchingCredential.certificatePath = matchObject.getCertificatePath();
                matchingCredential.locked = matchObject.getBooleanConditional(LOCKED_JSON);
                matchingCredentials.add(matchingCredential);
            }
        }


        public String getID() {
            return id;
        }

        public MatchingCredential[] getMatchingCredentials() {
            return matchingCredentials.toArray(new MatchingCredential[0]);
        }
    }

    private Vector<LookupResult> lookupResults = new Vector<LookupResult>();

    String clientSessionId;

    String serverSessionId;

    public LookupResult[] getLookupResults() {
        return lookupResults.toArray(new LookupResult[0]);
    }


    @Override
    protected void readJSONData(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Session properties
        /////////////////////////////////////////////////////////////////////////////////////////
        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        clientSessionId = getID(rd, CLIENT_SESSION_ID_JSON);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the lookup_results [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        JSONArrayReader lookups = rd.getArray(LOOKUP_RESULTS_JSON);
        do {
            LookupResult lookupResult = new LookupResult(lookups.getObject());
            lookupResults.add(lookupResult);
        }
        while (lookups.hasMore());
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.CREDENTIAL_DISCOVERY_RESPONSE.getName();
    }
}
