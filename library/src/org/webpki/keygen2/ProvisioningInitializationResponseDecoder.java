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

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSignatureDecoder;

import org.webpki.util.ISODateTime;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningInitializationResponseDecoder extends KeyGen2Validator {

    private static final long serialVersionUID = 1L;

    String serverSessionId;

    String clientSessionId;

    String serverTime;

    GregorianCalendar clientTime;

    ECPublicKey clientEphemeralKey;

    byte[] attestation;

    X509Certificate[] deviceCertificatePath;  // Is null for the privacy_enabled mode

    byte[] serverCertificateFingerprint;  // Optional

    JSONSignatureDecoder signature;

    public X509Certificate[] getDeviceCertificatePath() {
        return deviceCertificatePath;
    }

    @Override
    protected void readJSONData(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // The core session properties
        /////////////////////////////////////////////////////////////////////////////////////////
        attestation = rd.getBinary(ATTESTATION_JSON);

        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        clientSessionId = getID(rd, CLIENT_SESSION_ID_JSON);

        serverTime = rd.getString(SERVER_TIME_JSON);

        clientTime = rd.getDateTime(CLIENT_TIME_JSON, ISODateTime.LOCAL_NO_SUBSECONDS);

        serverCertificateFingerprint = rd.getBinaryConditional(SERVER_CERT_FP_JSON);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the ephemeral client key
        /////////////////////////////////////////////////////////////////////////////////////////
        clientEphemeralKey = (ECPublicKey) rd.getObject(CLIENT_EPHEMERAL_KEY_JSON)
                .getCorePublicKey(AlgorithmPreferences.JOSE_ACCEPT_PREFER);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional device certificate path
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasProperty(DEVICE_ID_JSON)) {
            deviceCertificatePath = rd.getObject(DEVICE_ID_JSON).getCertificatePath();
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the mandatory provisioning session data signature
        /////////////////////////////////////////////////////////////////////////////////////////
        signature = rd.getSignature(new JSONCryptoHelper.Options().setRequirePublicKeyInfo(false));
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.PROVISIONING_INITIALIZATION_RESPONSE.getName();
    }
}
