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

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.GregorianCalendar;
import java.util.LinkedHashMap;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;

import org.webpki.sks.AppUsage;
import org.webpki.sks.Grouping;

import org.webpki.util.ArrayUtil;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryRequestDecoder extends ClientDecoder {

    private static final long serialVersionUID = 1L;

    public class LookupSpecifier extends CertificateFilter {

        String id;

        GregorianCalendar issuedBefore;
        GregorianCalendar issuedAfter;
        Grouping grouping;
        AppUsage appUsage;

        PublicKey keyManagementKey;

        LookupSpecifier(JSONObjectReader rd) throws IOException {
            id = KeyGen2Validator.getID(rd, ID_JSON);
            if (!ArrayUtil.compare(nonce_reference, rd.getBinary(NONCE_JSON))) {
                throw new IOException("\"" + NONCE_JSON + "\"  error");
            }
            if (rd.hasProperty(SEARCH_FILTER_JSON)) {
                JSONObjectReader search = rd.getObject(SEARCH_FILTER_JSON);
                if (search.getProperties().length == 0) {
                    throw new IOException("Empty \"" + SEARCH_FILTER_JSON + "\" not allowed");
                }
                setFingerPrint(search.getBinaryConditional(CertificateFilter.CF_FINGER_PRINT));
                setIssuerRegEx(search.getStringConditional(CertificateFilter.CF_ISSUER_REG_EX));
                setSerialNumber(KeyGen2Validator.getBigIntegerConditional(search, CertificateFilter.CF_SERIAL_NUMBER));
                setSubjectRegEx(search.getStringConditional(CertificateFilter.CF_SUBJECT_REG_EX));
                setEmailRegEx(search.getStringConditional(CertificateFilter.CF_EMAIL_REG_EX));
                setPolicyRules(search.getStringArrayConditional(CertificateFilter.CF_POLICY_RULES));
                setKeyUsageRules(search.getStringArrayConditional(CertificateFilter.CF_KEY_USAGE_RULES));
                setExtendedKeyUsageRules(search.getStringArrayConditional(CertificateFilter.CF_EXT_KEY_USAGE_RULES));
                issuedBefore = KeyGen2Validator.getDateTimeConditional(search, ISSUED_BEFORE_JSON);
                issuedAfter = KeyGen2Validator.getDateTimeConditional(search, ISSUED_AFTER_JSON);
                if (search.hasProperty(GROUPING_JSON)) {
                    grouping = Grouping.getGroupingFromString(search.getString(GROUPING_JSON));
                }
                if (search.hasProperty(APP_USAGE_JSON)) {
                    appUsage = AppUsage.getAppUsageFromString(search.getString(APP_USAGE_JSON));
                }
            }
            JSONSignatureDecoder signature = rd.getSignature(new JSONCryptoHelper.Options());
            keyManagementKey = signature.getPublicKey();
            if (((AsymSignatureAlgorithms) signature.getAlgorithm()).getDigestAlgorithm() != HashAlgorithms.SHA256) {
                throw new IOException("Lookup signature must use SHA256");
            }
        }


        public String getID() {
            return id;
        }

        public PublicKey getKeyManagementKey() {
            return keyManagementKey;
        }

        public GregorianCalendar getIssuedBefore() {
            return issuedBefore;
        }

        public GregorianCalendar getIssuedAfter() {
            return issuedAfter;
        }

        public Grouping getGrouping() {
            return grouping;
        }

        public AppUsage getAppUsage() {
            return appUsage;
        }

        @Override
        public boolean matches(X509Certificate[] certificatePath) throws IOException {
            if (issuedBefore != null && issuedBefore.getTimeInMillis() < (certificatePath[0].getNotBefore().getTime())) {
                return false;
            }
            if (issuedAfter != null && issuedAfter.getTimeInMillis() > (certificatePath[0].getNotBefore().getTime())) {
                return false;
            }
            return super.matches(certificatePath);
        }
    }

    LinkedHashMap<String, LookupSpecifier> lookupSpecifiers = new LinkedHashMap<String, LookupSpecifier>();

    String clientSessionId;

    String serverSessionId;

    String submitUrl;

    byte[] nonce_reference;

    public String getServerSessionId() {
        return serverSessionId;
    }


    public String getClientSessionId() {
        return clientSessionId;
    }


    public String getSubmitUrl() {
        return submitUrl;
    }


    public LookupSpecifier[] getLookupSpecifiers() {
        return lookupSpecifiers.values().toArray(new LookupSpecifier[0]);
    }


    @Override
    void readServerRequest(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Session properties
        /////////////////////////////////////////////////////////////////////////////////////////
        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        clientSessionId = getID(rd, CLIENT_SESSION_ID_JSON);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Calculate proper nonce
        /////////////////////////////////////////////////////////////////////////////////////////
        MacGenerator mac = new MacGenerator();
        mac.addString(clientSessionId);
        mac.addString(serverSessionId);
        nonce_reference = HashAlgorithms.SHA256.digest(mac.getResult());

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the lookup specifiers [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader spec : getObjectArray(rd, LOOKUP_SPECIFIERS_JSON)) {
            LookupSpecifier ls = new LookupSpecifier(spec);
            if (lookupSpecifiers.put(ls.id, ls) != null) {
                throw new IOException("Duplicate id: " + ls.id);
            }
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.CREDENTIAL_DISCOVERY_REQUEST.getName();
    }
}
