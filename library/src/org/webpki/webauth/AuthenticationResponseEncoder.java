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
package org.webpki.webauth;

import java.security.cert.X509Certificate;

import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONX509Signer;

import org.webpki.util.ISODateTime;

import static org.webpki.webauth.WebAuthConstants.*;


public class AuthenticationResponseEncoder extends JSONEncoder {

    private GregorianCalendar serverTime;

    private GregorianCalendar clientTime;

    byte[] serverCertificateFingerprint;

    LinkedHashMap<String, LinkedHashSet<String>> clientPlatformFeatures = new LinkedHashMap<>();

    String id;

    JSONX509Signer signer;


    public AuthenticationResponseEncoder(JSONX509Signer signer,
                                         AuthenticationRequestDecoder auth_req_decoder,
                                         GregorianCalendar clientTime,
                                         X509Certificate server_certificate) {
        this.signer = signer;
        this.id = auth_req_decoder.getID();
        this.serverTime = auth_req_decoder.getServerTime();
        this.clientTime = clientTime;
        if (server_certificate != null) {
            this.serverCertificateFingerprint = 
                    HashAlgorithms.SHA256.digest(CertificateUtil.getBlobFromCertificate(server_certificate));
        }
    }

    public AuthenticationResponseEncoder addClientFeature(String type, String value) {
        LinkedHashSet<String> set = clientPlatformFeatures.get(type);
        if (set == null) {
            clientPlatformFeatures.put(type, set = new LinkedHashSet<>());
        }
        set.add(value);
        return this;
    }

    @Override
    protected void writeJSONData(JSONObjectWriter wr) {
        wr.setString(ID_JSON, id);

        wr.setDateTime(SERVER_TIME_JSON, serverTime, ISODateTime.UTC_NO_SUBSECONDS);

        wr.setDateTime(CLIENT_TIME_JSON, clientTime, ISODateTime.LOCAL_NO_SUBSECONDS);

        if (serverCertificateFingerprint != null) {
            wr.setBinary(SERVER_CERT_FP_JSON, serverCertificateFingerprint);
        }

        if (!clientPlatformFeatures.isEmpty()) {
            JSONArrayWriter features = wr.setArray(CLIENT_FEATURES_JSON);
            for (String type : clientPlatformFeatures.keySet()) {
                JSONArrayWriter arr = features.setObject().setArray(TYPE_JSON);
                for (String value : clientPlatformFeatures.get(type)) {
                    arr.setString(value);
                }
            }
        }

        wr.setSignature(signer);
    }

    @Override
    public String getContext() {
        return WebAuthConstants.WEBAUTH_NS;
    }

    @Override
    public String getQualifier() {
        return AUTHENTICATION_RESPONSE_MS;
    }
}
