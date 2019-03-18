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

import java.security.interfaces.RSAPublicKey;

import java.util.GregorianCalendar;
import java.util.Vector;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONObjectWriter;

import org.webpki.keygen2.ServerState.ProtocolPhase;

import org.webpki.sks.AppUsage;
import org.webpki.sks.Grouping;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryRequestEncoder extends ServerEncoder {

    private static final long serialVersionUID = 1L;

    ServerCryptoInterface serverCryptoInterface;

    String serverSessionId;

    String clientSessionId;

    public class LookupDescriptor extends CertificateFilter implements AsymKeySignerInterface {

        PublicKey keyManagementKey;

        String id;

        boolean searchFilter;

        GregorianCalendar issuedBefore;
        GregorianCalendar issuedAfter;
        Grouping grouping;
        AppUsage appUsage;

        LookupDescriptor(PublicKey keyManagementKey) {
            this.keyManagementKey = keyManagementKey;
            this.id = lookupPrefix + ++nextLookupIdSuffix;
        }

        @Override
        protected void nullCheck(Object object) throws IOException {
            searchFilter = true;
            if (object == null) {
                bad("Null search parameter not allowed");
            }
        }


        public LookupDescriptor setIssuedBefore(GregorianCalendar issuedBefore) throws IOException {
            nullCheck(issuedBefore);
            searchFilter = true;
            this.issuedBefore = issuedBefore;
            return this;
        }

        public LookupDescriptor setIssuedAfter(GregorianCalendar issuedAfter) throws IOException {
            nullCheck(issuedAfter);
            searchFilter = true;
            this.issuedAfter = issuedAfter;
            return this;
        }

        public LookupDescriptor setGrouping(Grouping grouping) throws IOException {
            nullCheck(grouping);
            searchFilter = true;
            this.grouping = grouping;
            return this;
        }

        public LookupDescriptor setAppUsage(AppUsage appUsage) throws IOException {
            nullCheck(appUsage);
            searchFilter = true;
            this.appUsage = appUsage;
            return this;
        }

        void write(JSONObjectWriter wr) throws IOException {
            wr.setString(ID_JSON, id);

            wr.setBinary(NONCE_JSON, nonce);

            if (searchFilter) {
                JSONObjectWriter searchWriter = wr.setObject(SEARCH_FILTER_JSON);
                setOptionalBinary(searchWriter, CertificateFilter.CF_FINGER_PRINT, getFingerPrint());
                setOptionalString(searchWriter, CertificateFilter.CF_ISSUER_REG_EX, getIssuerRegEx());
                setOptionalBigInteger(searchWriter, CertificateFilter.CF_SERIAL_NUMBER, getSerialNumber());
                setOptionalString(searchWriter, CertificateFilter.CF_SUBJECT_REG_EX, getSubjectRegEx());
                setOptionalString(searchWriter, CertificateFilter.CF_EMAIL_REG_EX, getEmailRegEx());
                setOptionalStringArray(searchWriter, CertificateFilter.CF_POLICY_RULES, getPolicyRules());
                setOptionalStringArray(searchWriter, CertificateFilter.CF_KEY_USAGE_RULES, getKeyUsageRules());
                setOptionalStringArray(searchWriter, CertificateFilter.CF_EXT_KEY_USAGE_RULES, getExtendedKeyUsageRules());
                setOptionalDateTime(searchWriter, ISSUED_BEFORE_JSON, issuedBefore);
                setOptionalDateTime(searchWriter, ISSUED_AFTER_JSON, issuedAfter);
                if (grouping != null) {
                    searchWriter.setString(GROUPING_JSON, grouping.getProtocolName());
                }
                if (appUsage != null) {
                    searchWriter.setString(APP_USAGE_JSON, appUsage.getProtocolName());
                }
            }
            JSONAsymKeySigner signer = new JSONAsymKeySigner(this);
            signer.setSignatureAlgorithm(keyManagementKey instanceof RSAPublicKey ?
                    AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256);
            wr.setSignature(signer);
        }

        @Override
        public PublicKey getPublicKey() throws IOException {
            return keyManagementKey;
        }

        @Override
        public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
            return serverCryptoInterface.generateKeyManagementAuthorization(keyManagementKey, data);
        }
    }


    Vector<LookupDescriptor> lookupDescriptors = new Vector<LookupDescriptor>();

    String lookupPrefix = "Lookup.";

    byte[] nonce;

    int nextLookupIdSuffix = 0;

    // Constructors

    public CredentialDiscoveryRequestEncoder(ServerState serverState) throws IOException {
        serverState.checkState(true, ProtocolPhase.CREDENTIAL_DISCOVERY);
        clientSessionId = serverState.clientSessionId;
        serverSessionId = serverState.serverSessionId;
        serverCryptoInterface = serverState.serverCryptoInterface;
    }


    public LookupDescriptor addLookupDescriptor(PublicKey keyManagementKey) {
        LookupDescriptor lo_des = new LookupDescriptor(keyManagementKey);
        lookupDescriptors.add(lo_des);
        return lo_des;
    }


    @Override
    void writeServerRequest(JSONObjectWriter wr) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, serverSessionId);

        wr.setString(CLIENT_SESSION_ID_JSON, clientSessionId);

        ////////////////////////////////////////////////////////////////////////
        // Lookup descriptors
        ////////////////////////////////////////////////////////////////////////
        if (lookupDescriptors.isEmpty()) {
            bad("There must be at least one descriptor defined");
        }
        MacGenerator concat = new MacGenerator();
        concat.addString(clientSessionId);
        concat.addString(serverSessionId);
        nonce = HashAlgorithms.SHA256.digest(concat.getResult());
        JSONArrayWriter array = wr.setArray(LOOKUP_SPECIFIERS_JSON);
        for (LookupDescriptor imDes : lookupDescriptors) {
            imDes.write(array.setObject());
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.CREDENTIAL_DISCOVERY_REQUEST.getName();
    }
}
