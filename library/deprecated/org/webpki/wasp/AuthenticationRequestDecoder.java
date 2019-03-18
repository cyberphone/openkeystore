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
package org.webpki.wasp;

import java.io.IOException;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.CanonicalizationAlgorithms;
import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationRequestDecoder extends AuthenticationRequest {
    private String serverTime;

    private XMLSignatureWrapper signature;                                              // Optional

    private void readAuthenticationProfile(DOMReaderHelper rd) throws IOException {
        rd.getNext(AUTHENTICATION_PROFILE_ELEM);
        DOMAttributeReaderHelper ah = rd.getAttributeHelper();
        AuthenticationProfile ap = new AuthenticationProfile();

        ap.signed_key_info = ah.getBooleanConditional(SIGNED_KEY_INFO_ATTR);

        ap.extendedCertPath = ah.getBooleanConditional(EXTENDED_CERT_PATH_ATTR);

        String value;

        if ((value = ah.getStringConditional(CN_ALG_ATTR)) != null) {
            if (CanonicalizationAlgorithms.testAlgorithmURI(value)) {
                ap.canonicalization_algorithm = CanonicalizationAlgorithms.getAlgorithmFromURI(value);
            } else {
                return;
            }
        }

        if ((value = ah.getStringConditional(DIGEST_ALG_ATTR)) != null) {
            if (HashAlgorithms.testAlgorithmURI(value)) {
                ap.digest_algorithm = HashAlgorithms.getAlgorithmFromID(value);
            } else {
                return;
            }
        }

        if ((value = ah.getStringConditional(SIGNATURE_ALG_ATTR)) != null) {
            if (AsymSignatureAlgorithms.testAlgorithmURI(value)) {
                ap.signatureAlgorithm = AsymSignatureAlgorithms.getAlgorithmFromID(value, AlgorithmPreferences.SKS);
            } else {
                return;
            }
        }

        authentication_profiles.add(ap);
    }


    public AuthenticationProfile[] getAuthenticationProfiles() {
        return authentication_profiles.toArray(new AuthenticationProfile[0]);
    }


    public CertificateFilter[] getCertificateFilters() {
        return certificateFilters.toArray(new CertificateFilter[0]);
    }


    public String getID() {
        return id;
    }


    public String getServerTime() {
        return serverTime;
    }


    public String getSubmitUrl() {
        return submitUrl;
    }


    public String getAbortURL() {
        return abortUrl;
    }


    public String[] getRequestedClientPlatformFeatures() {
        return requested_client_platform_features.toArray(new String[0]);
    }


    public String[] getLanguages() {
        return languages;
    }


    public int getExpires() {
        return expires;
    }


    public void verifySignature(VerifierInterface verifier) throws IOException {
        new XMLVerifier(verifier).validateEnvelopedSignature(this, null, signature, id);
    }


    public boolean isSigned() {
        return signature != null;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML(DOMReaderHelper rd) throws IOException {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        id = ah.getString(ID_ATTR);

        serverTime = ah.getString(SERVER_TIME_ATTR);

        submitUrl = ah.getString(SUBMIT_URL_ATTR);

        abortUrl = ah.getStringConditional(ABORT_URL_ATTR);

        languages = ah.getListConditional(LANGUAGES_ATTR);

        expires = ah.getIntConditional(EXPIRES_ATTR, -1);  // Default: no timeout and associated GUI

        //////////////////////////////////////////////////////////////////////////
        // Optional "client platform features"
        //////////////////////////////////////////////////////////////////////////
        String[] features = ah.getListConditional(CLIENT_PLATFORM_FEATURES_ATTR);
        if (features != null) for (String feature : features) {
            requested_client_platform_features.add(feature);
        }

        rd.getChild();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the authentication profiles [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        do {
            readAuthenticationProfile(rd);
        }
        while (rd.hasNext(AUTHENTICATION_PROFILE_ELEM));
        if (authentication_profiles.isEmpty()) {
            throw new IOException("No matching AuthenticationProfile found");
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the certificate filters [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext(CERTIFICATE_FILTER_ELEM)) {
            certificateFilters.add(SignatureRequestDecoder.readCertificateFilter(rd));
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext(XMLSignatureWrapper.SIGNATURE_ELEM)) {
            signature = (XMLSignatureWrapper) wrap(rd.getNext());
        }
    }
}
