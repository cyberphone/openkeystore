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
package org.webpki.sks;

import java.security.PublicKey;

public class EnumeratedProvisioningSession {

    public static final int INIT_ENUMERATION = 0;

    int provisioningHandle = INIT_ENUMERATION;

    public int getProvisioningHandle() {
        return provisioningHandle;
    }


    String sessionKeyAlgorithm;

    public String getSessionKeyAlgorithm() {
        return sessionKeyAlgorithm;
    }


    boolean privacyEnabled;

    public boolean getPrivacyEnabled() {
        return privacyEnabled;
    }


    PublicKey keyManagementKey;

    public PublicKey getKeyManagementKey() {
        return keyManagementKey;
    }


    int clientTime;

    public int getClientTime() {
        return clientTime;
    }


    int sessionLifeTime;

    public int getSessionLifeTime() {
        return sessionLifeTime;
    }


    String clientSessionId;

    public String getClientSessionId() {
        return clientSessionId;
    }


    String serverSessionId;

    public String getServerSessionId() {
        return serverSessionId;
    }


    String issuerUri;

    public String getIssuerUri() {
        return issuerUri;
    }


    public EnumeratedProvisioningSession() {
    }


    public EnumeratedProvisioningSession(int provisioningHandle,
                                         String sessionKeyAlgorithm,
                                         boolean privacyEnabled,
                                         PublicKey keyManagementKey,
                                         int clientTime,
                                         int sessionLifeTime,
                                         String serverSessionId,
                                         String clientSessionId,
                                         String issuerUri) {
        this.sessionKeyAlgorithm = sessionKeyAlgorithm;
        this.privacyEnabled = privacyEnabled;
        this.keyManagementKey = keyManagementKey;
        this.clientTime = clientTime;
        this.sessionLifeTime = sessionLifeTime;
        this.provisioningHandle = provisioningHandle;
        this.clientSessionId = clientSessionId;
        this.serverSessionId = serverSessionId;
        this.issuerUri = issuerUri;
    }

}
