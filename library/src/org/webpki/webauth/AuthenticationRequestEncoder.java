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
import java.util.LinkedHashSet;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.KeyContainerTypes;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

import static org.webpki.webauth.WebAuthConstants.*;

public class AuthenticationRequestEncoder extends ServerEncoder {

    private static final long serialVersionUID = 1L;

    String id;

    String submitUrl;

    String abortUrl;                                                          // Optional

    String[] languageList;                                                    // Optional

    String[] keyContainerList;                                                // Optional

    boolean fullPath;                                                         // Optional

    boolean extendedCertPathSet;                                              // Optional
    boolean extendedCertPath;

    int expires;

    LinkedHashSet<AsymSignatureAlgorithms> signatureAlgorithms = new LinkedHashSet<AsymSignatureAlgorithms>();

    Vector<CertificateFilter> certificateFilters = new Vector<CertificateFilter>();

    Vector<String> requestedClientFeatures = new Vector<String>();

    String serverTime;

    public AuthenticationRequestEncoder(String submitUrl, String optionalAbortUrl) {
        this.submitUrl = submitUrl;
        this.abortUrl = optionalAbortUrl;
        this.serverTime = 
                ISODateTime.formatDateTime(new GregorianCalendar(), ISODateTime.UTC_NO_SUBSECONDS);
    }


    public AuthenticationRequestEncoder addSignatureAlgorithm(AsymSignatureAlgorithms algorithm) {
        signatureAlgorithms.add(algorithm);
        return this;
    }


    public AuthenticationRequestEncoder addCertificateFilter(CertificateFilter certificateFilter) {
        certificateFilters.add(certificateFilter);
        return this;
    }


    public AuthenticationRequestEncoder setExtendedCertPath(boolean extendedCertPath) {
        this.extendedCertPath = extendedCertPath;
        extendedCertPathSet = true;
        return this;
    }

    public AuthenticationRequestEncoder setTargetKeyContainerList(KeyContainerTypes[] optionalListOfGrantedTypes) throws IOException {
        this.keyContainerList = KeyContainerTypes.parseOptionalKeyContainerList(optionalListOfGrantedTypes);
        return this;
    }

    public AuthenticationRequestEncoder setID(String id) {
        this.id = id;
        return this;
    }


    public AuthenticationRequestEncoder setPreferredLanguages(String[] languageList) {
        this.languageList = languageList;
        return this;
    }


    public AuthenticationRequestEncoder requestClientFeature(String featureUri) {
        requestedClientFeatures.add(featureUri);
        return this;
    }

    public void checkRequestResponseIntegrity(AuthenticationResponseDecoder authenticationResponse,
                                              byte[] expectedServerCertificateFingerprint) throws IOException {
        if (expectedServerCertificateFingerprint != null &&
                (authenticationResponse.serverCertificateFingerprint == null ||
                        !ArrayUtil.compare(authenticationResponse.serverCertificateFingerprint,
                                expectedServerCertificateFingerprint))) {
            bad("Server certificate fingerprint");
        }
        if (!id.equals(authenticationResponse.id)) {
            bad("ID attributes");
        }
        if (!serverTime.equals(authenticationResponse.serverTime)) {
            bad("ServerTime attribute");
        }
        boolean sigAlgFound = false;
        for (AsymSignatureAlgorithms sigAlg : signatureAlgorithms) {
            if (sigAlg == authenticationResponse.signatureAlgorithm) {
                sigAlgFound = true;
                break;
            }
        }
        if (!sigAlgFound) {
            bad("Wrong signature algorithm: " + authenticationResponse.signatureAlgorithm);
        }
        if (extendedCertPath && certificateFilters.size() > 0 && authenticationResponse.certificatePath != null) {
            for (CertificateFilter cf : certificateFilters) {
                if (cf.matches(authenticationResponse.certificatePath)) {
                    return;
                }
            }
            bad("Certificates does not match filter(s)");
        }
    }

    @Override
    void writeServerRequest(JSONObjectWriter wr) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        if (id == null) {
            id = Long.toHexString(new GregorianCalendar().getTimeInMillis());
            id += Base64URL.generateURLFriendlyRandom(MAX_ID_LENGTH - id.length());
        }
        wr.setString(ID_JSON, id);

        wr.setString(SERVER_TIME_JSON, serverTime);

        wr.setString(SUBMIT_URL_JSON, submitUrl);

        if (abortUrl != null) {
            wr.setString(ABORT_URL_JSON, abortUrl);
        }

        if (languageList != null) {
            wr.setStringArray(PREFERRED_LANGUAGES_JSON, languageList);
        }

        if (keyContainerList != null) {
            wr.setStringArray(KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS, keyContainerList);
        }

        if (expires > 0) {
            wr.setInt(EXPIRES_JSON, expires);
        }

        if (extendedCertPathSet) {
            wr.setBoolean(EXTENDED_CERT_PATH_JSON, extendedCertPath);
        }

        if (signatureAlgorithms.isEmpty()) {
            bad("Missing \"" + SIGNATURE_ALGORITHMS_JSON + "\"");
        }
        JSONArrayWriter signature_algorithm_array = wr.setArray(SIGNATURE_ALGORITHMS_JSON);
        for (AsymSignatureAlgorithms algorithm : signatureAlgorithms) {
            signature_algorithm_array.setString(algorithm.getAlgorithmId(AlgorithmPreferences.JOSE_ACCEPT_PREFER));
        }

        //////////////////////////////////////////////////////////////////////////
        // Optional "client platform features"
        //////////////////////////////////////////////////////////////////////////
        if (!requestedClientFeatures.isEmpty()) {
            wr.setStringArray(REQUESTED_CLIENT_FEATURES_JSON, requestedClientFeatures.toArray(new String[0]));
        }

        //////////////////////////////////////////////////////////////////////////
        // Certificate filters (optional)
        //////////////////////////////////////////////////////////////////////////
        if (!certificateFilters.isEmpty()) {
            JSONArrayWriter cf_arr = wr.setArray(CERTIFICATE_FILTERS_JSON);
            for (CertificateFilter cf : certificateFilters) {
                CertificateFilterWriter.write(cf_arr.setObject(), cf);
            }
        }
    }

    @Override
    public String getQualifier() {
        return AUTHENTICATION_REQUEST_MSG;
    }
}
