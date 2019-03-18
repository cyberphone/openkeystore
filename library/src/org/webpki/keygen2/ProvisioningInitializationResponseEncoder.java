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

import java.util.GregorianCalendar;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSymKeySigner;

import org.webpki.util.ISODateTime;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningInitializationResponseEncoder extends JSONEncoder {

    private static final long serialVersionUID = 1L;

    String serverSessionId;

    String clientSessionId;

    String serverTimeVerbatim;

    GregorianCalendar clientTime;

    ECPublicKey clientEphemeralKey;

    byte[] attestation;

    X509Certificate[] deviceCertificatePath;  // Is null for the privacy_enabled mode

    byte[] serverCertificateFingerprint;  // Optional

    JSONSymKeySigner sessionSignature;


    // Constructors

    public ProvisioningInitializationResponseEncoder(ProvisioningInitializationRequestDecoder prov_init_req,
                                                     ECPublicKey clientEphemeralKey,
                                                     String clientSessionId,
                                                     GregorianCalendar clientTime,
                                                     byte[] attestation,
                                                     X509Certificate[] deviceCertificatePath) throws IOException {
        this.serverSessionId = prov_init_req.serverSessionId;
        this.serverTimeVerbatim = prov_init_req.serverTimeVerbatim;
        this.clientEphemeralKey = clientEphemeralKey;
        this.clientSessionId = clientSessionId;
        this.clientTime = clientTime;
        this.attestation = attestation;
        this.deviceCertificatePath = deviceCertificatePath;
    }


    public void setServerCertificate(X509Certificate serverCertificate) throws IOException {
        try {
            serverCertificateFingerprint = HashAlgorithms.SHA256.digest(serverCertificate.getEncoded());
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse);
        }
    }


    public void setResponseSigner(SymKeySignerInterface signer) throws IOException {
        sessionSignature = new JSONSymKeySigner(signer);
    }


    @Override
    protected void writeJSONData(JSONObjectWriter wr) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, serverSessionId);

        wr.setString(CLIENT_SESSION_ID_JSON, clientSessionId);

        wr.setString(SERVER_TIME_JSON, serverTimeVerbatim);

        wr.setDateTime(CLIENT_TIME_JSON, clientTime, ISODateTime.LOCAL_NO_SUBSECONDS);

        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.setObject(CLIENT_EPHEMERAL_KEY_JSON,
                     JSONObjectWriter.createCorePublicKey(clientEphemeralKey,
                                                          AlgorithmPreferences.JOSE_ACCEPT_PREFER));

        ////////////////////////////////////////////////////////////////////////
        // Optional device certificate path
        ////////////////////////////////////////////////////////////////////////
        if (deviceCertificatePath != null) {
            wr.setObject(DEVICE_ID_JSON).setCertificatePath(deviceCertificatePath);
        }

        ////////////////////////////////////////////////////////////////////////
        // "Logical" position for the attestation
        ////////////////////////////////////////////////////////////////////////
        wr.setBinary(ATTESTATION_JSON, attestation);

        ////////////////////////////////////////////////////////////////////////
        // Optional server certificate fingerprint
        ////////////////////////////////////////////////////////////////////////
        if (serverCertificateFingerprint != null) {
            wr.setBinary(SERVER_CERT_FP_JSON, serverCertificateFingerprint);
        }

        ////////////////////////////////////////////////////////////////////////
        // Mandatory session signature
        ////////////////////////////////////////////////////////////////////////
        wr.setSignature(sessionSignature);
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.PROVISIONING_INITIALIZATION_RESPONSE.getName();
    }

    @Override
    public String getContext() {
        return KEYGEN2_NS;
    }
}
