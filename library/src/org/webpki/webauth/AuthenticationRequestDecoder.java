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
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyContainerTypes;

import org.webpki.json.JSONObjectReader;

import org.webpki.util.ISODateTime;

import static org.webpki.webauth.WebAuthConstants.*;


public class AuthenticationRequestDecoder extends ClientDecoder {

    private static final long serialVersionUID = 1L;

    GregorianCalendar serverTime;

    String id;

    LinkedHashSet<AsymSignatureAlgorithms> algorithms = new LinkedHashSet<AsymSignatureAlgorithms>();

    LinkedHashSet<String> clientFeatures = new LinkedHashSet<String>();

    Vector<CertificateFilter> certificateFilters = new Vector<CertificateFilter>();

    String submitUrl;

    String abortUrl;

    String[] languages;

    LinkedHashSet<KeyContainerTypes> keyContainerList;

    int expires;

    boolean extendedCertPath;

    public AsymSignatureAlgorithms[] getSignatureAlgorithms() {
        return algorithms.toArray(new AsymSignatureAlgorithms[0]);
    }


    public CertificateFilter[] getCertificateFilters() {
        return certificateFilters.toArray(new CertificateFilter[0]);
    }


    public LinkedHashSet<KeyContainerTypes> getOptionalKeyContainerList() {
        return keyContainerList;
    }


    public String getID() {
        return id;
    }


    public GregorianCalendar getServerTime() {
        return serverTime;
    }


    public String getSubmitUrl() {
        return submitUrl;
    }


    public String getOptionalAbortURL() {
        return abortUrl;
    }


    public String[] getRequestedClientFeatures() {
        return clientFeatures.toArray(new String[0]);
    }


    public String[] getOptionalLanguageList() {
        return languages;
    }


    public int getExpires() {
        return expires;
    }

    public boolean wantsExtendedCertPath() {
        return extendedCertPath;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // JSON Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    void readServerRequest(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level properties
        /////////////////////////////////////////////////////////////////////////////////////////
        id = InputValidator.getID(rd, ID_JSON);

        serverTime = rd.getDateTime(SERVER_TIME_JSON, ISODateTime.UTC_NO_SUBSECONDS);

        submitUrl = rd.getString(SUBMIT_URL_JSON);

        abortUrl = rd.getStringConditional(ABORT_URL_JSON);

        languages = InputValidator.getListConditional(rd, PREFERRED_LANGUAGES_JSON);

        keyContainerList = KeyContainerTypes.getOptionalKeyContainerSet(InputValidator.getListConditional(rd, KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS));

        extendedCertPath = rd.getBooleanConditional(EXTENDED_CERT_PATH_JSON);

        expires = rd.hasProperty(EXPIRES_JSON) ? rd.getInt(EXPIRES_JSON) : -1;  // Default: no timeout and associated GUI

        /////////////////////////////////////////////////////////////////////////////////////////
        // Optional client features [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        String[] features = InputValidator.getURIListConditional(rd, CLIENT_FEATURES_JSON);
        if (features != null) for (String feature : features) {
            if (!clientFeatures.add(feature)) {
                bad("Duplicate \"" + CLIENT_FEATURES_JSON + "\"  :" + feature);
            }
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature algorithms [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (String sig_alg_string : InputValidator.getNonEmptyList(rd, SIGNATURE_ALGORITHMS_JSON)) {
            AsymSignatureAlgorithms sig_alg = AsymSignatureAlgorithms.getAlgorithmFromId(sig_alg_string, AlgorithmPreferences.JOSE_ACCEPT_PREFER);
            if (!algorithms.add(sig_alg)) {
                bad("Duplicate \"" + SIGNATURE_ALGORITHMS_JSON + "\" : " + sig_alg_string);
            }
            if (sig_alg.getDigestAlgorithm() == null) {
                bad("Not a proper signature algorithm: " + sig_alg_string);
            }
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional certificate filters [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader cf : InputValidator.getObjectArrayConditional(rd, CERTIFICATE_FILTERS_JSON)) {
            certificateFilters.add(CertificateFilterReader.read(cf));
        }
    }

    @Override
    public String getQualifier() {
        return AUTHENTICATION_REQUEST_MSG;
    }
}
