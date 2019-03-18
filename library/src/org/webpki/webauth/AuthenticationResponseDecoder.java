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
package org.webpki.webauth;

import java.io.IOException;

import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.VerifierInterface;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONX509Verifier;

import org.webpki.util.ISODateTime;

import static org.webpki.webauth.WebAuthConstants.*;


public class AuthenticationResponseDecoder extends InputValidator {

    private static final long serialVersionUID = 1L;

    String serverTime;

    private GregorianCalendar clientTime;

    private JSONSignatureDecoder signature;

    byte[] serverCertificateFingerprint;

    String requestUrl;

    String id;

    X509Certificate[] certificatePath;

    AsymSignatureAlgorithms signatureAlgorithm;

    LinkedHashMap<String, LinkedHashSet<String>> clientPlatformFeatures = new LinkedHashMap<String, LinkedHashSet<String>>();


    public String getRequestURL() {
        return requestUrl;
    }


    public GregorianCalendar getClientTime() {
        return clientTime;
    }


    public String getID() {
        return id;
    }


    public LinkedHashMap<String, LinkedHashSet<String>> getClientPlatformFeatures() {
        return clientPlatformFeatures;
    }


    public void verifySignature(VerifierInterface verifier) throws IOException {
        signature.verify(new JSONX509Verifier(verifier));
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // JSON Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    protected void readJSONData(JSONObjectReader rd) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level properties
        //////////////////////////////////////////////////////////////////////////
        id = rd.getString(ID_JSON);

        serverTime = rd.getString(SERVER_TIME_JSON);

        clientTime = rd.getDateTime(CLIENT_TIME_JSON, ISODateTime.LOCAL_NO_SUBSECONDS);

        requestUrl = rd.getString(REQUEST_URL_JSON);

        serverCertificateFingerprint = rd.getBinaryConditional(SERVER_CERT_FP_JSON);

        //////////////////////////////////////////////////////////////////////////
        // Get the optional client platform features
        //////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader feature : InputValidator.getObjectArrayConditional(rd, CLIENT_FEATURES_JSON)) {
            String type = InputValidator.getURI(feature, TYPE_JSON);
            LinkedHashSet<String> set = clientPlatformFeatures.get(type);
            if (set != null) {
                bad("Duplicated \"" + TYPE_JSON + "\" : " + type);
            }
            clientPlatformFeatures.put(type, set = new LinkedHashSet<String>());
            for (String value : InputValidator.getNonEmptyList(feature, VALUES_JSON)) {
                set.add(value);
            }
        }

        //////////////////////////////////////////////////////////////////////////
        // Finally, get the signature!
        //////////////////////////////////////////////////////////////////////////
        signature = rd.getSignature(new JSONCryptoHelper.Options());
        certificatePath = signature.getCertificatePath();
        signatureAlgorithm = (AsymSignatureAlgorithms) signature.getAlgorithm();
    }

    @Override
    public String getQualifier() {
        return AUTHENTICATION_RESPONSE_MS;
    }
}
