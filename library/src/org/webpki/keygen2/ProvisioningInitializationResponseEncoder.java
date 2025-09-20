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

import java.util.GregorianCalendar;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ISODateTime;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningInitializationResponseEncoder extends JSONEncoder {

    String serverSessionId;

    String clientSessionId;

    String serverTimeVerbatim;

    GregorianCalendar clientTime;

    ECPublicKey clientEphemeralKey;

    byte[] attestation;

    X509Certificate[] deviceCertificatePath;  // Is null for the privacy_enabled mode

    // Constructors

    public ProvisioningInitializationResponseEncoder(ProvisioningInitializationRequestDecoder prov_init_req,
                                                     ECPublicKey clientEphemeralKey,
                                                     String clientSessionId,
                                                     GregorianCalendar clientTime,
                                                     byte[] attestation,
                                                     X509Certificate[] deviceCertificatePath) {
        this.serverSessionId = prov_init_req.serverSessionId;
        this.serverTimeVerbatim = prov_init_req.serverTimeVerbatim;
        this.clientEphemeralKey = clientEphemeralKey;
        this.clientSessionId = clientSessionId;
        this.clientTime = clientTime;
        this.attestation = attestation;
        this.deviceCertificatePath = deviceCertificatePath;
    }

    @Override
    protected void writeJSONData(JSONObjectWriter wr) {
        //======================================================================//
        // Session properties
        //======================================================================//
        wr.setString(SERVER_SESSION_ID_JSON, serverSessionId);

        wr.setString(CLIENT_SESSION_ID_JSON, clientSessionId);

        wr.setString(SERVER_TIME_JSON, serverTimeVerbatim);

        wr.setDateTime(CLIENT_TIME_JSON, clientTime, ISODateTime.LOCAL_NO_SUBSECONDS);

        //====================================================================//
        // Server ephemeral key
        //====================================================================//
        wr.setObject(CLIENT_EPHEMERAL_KEY_JSON,
                     JSONObjectWriter.createCorePublicKey(clientEphemeralKey,
                                                          AlgorithmPreferences.JOSE_ACCEPT_PREFER));

        //====================================================================//
        // Optional device certificate path
        //====================================================================//
        if (deviceCertificatePath != null) {
            wr.setObject(DEVICE_ID_JSON).setCertificatePath(deviceCertificatePath);
        }

        //====================================================================//
        // "Logical" position for the attestation
        //====================================================================//
        wr.setBinary(ATTESTATION_JSON, attestation);
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
