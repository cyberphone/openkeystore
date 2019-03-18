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

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.util.Vector;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationRequestEncoder extends ServerEncoder {

    private static final long serialVersionUID = 1L;

    ServerState serverState;

    KeyManagementKeyUpdateHolder kmkRoot;

    public class KeyManagementKeyUpdateHolder {

        PublicKey keyManagementKey;

        byte[] authorization;

        Vector<KeyManagementKeyUpdateHolder> children = new Vector<KeyManagementKeyUpdateHolder>();

        KeyManagementKeyUpdateHolder(PublicKey keyManagementKey) {
            this.keyManagementKey = keyManagementKey;
        }

        public KeyManagementKeyUpdateHolder update(PublicKey keyManagementKey) throws IOException {
            KeyManagementKeyUpdateHolder kmk = new KeyManagementKeyUpdateHolder(keyManagementKey);
            kmk.authorization = serverState.serverCryptoInterface.generateKeyManagementAuthorization(keyManagementKey,
                    ArrayUtil.add(SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION,
                            this.keyManagementKey.getEncoded()));
            children.add(kmk);
            return kmk;
        }

        public KeyManagementKeyUpdateHolder update(PublicKey keyManagementKey, 
                                                   byte[] externalAuthorization) throws IOException {
            KeyManagementKeyUpdateHolder kmk = new KeyManagementKeyUpdateHolder(keyManagementKey);
            kmk.authorization = externalAuthorization;
            try {
                SignatureWrapper kmkVerify =
                    new SignatureWrapper(keyManagementKey instanceof RSAPublicKey ?
                                               AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256,
                                         keyManagementKey);
                kmkVerify.update(SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION);
                kmkVerify.update(this.keyManagementKey.getEncoded());
                if (!kmkVerify.verify(externalAuthorization)) {
                    throw new IOException("Authorization signature did not validate");
                }
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
            children.add(kmk);
            return kmk;
        }
    }

    // Constructors

    public ProvisioningInitializationRequestEncoder(ServerState serverState,
                                                    int sessionLifeTime,
                                                    short sessionKeyLimit) throws IOException {
        serverState.checkState(true, ProtocolPhase.PROVISIONING_INITIALIZATION);
        this.serverState = serverState;
        this.sessionLifeTime = serverState.sessionLifeTime = sessionLifeTime;
        this.sessionKeyLimit = serverState.sessionKeyLimit = sessionKeyLimit;
        serverSessionId = serverState.serverSessionId;
        serverEphemeralKey = serverState.serverEphemeralKey = serverState.generateEphemeralKey();
    }


    public KeyManagementKeyUpdateHolder setKeyManagementKey(PublicKey keyManagementKey) {
        return kmkRoot = new KeyManagementKeyUpdateHolder(serverState.keyManagementKey = keyManagementKey);
    }


    public void setSessionKeyAlgorithm(String sessionKeyAlgorithm) {
        serverState.provisioningSessionAlgorithm = sessionKeyAlgorithm;
    }


    private void scanForUpdatedKeys(JSONObjectWriter wr, KeyManagementKeyUpdateHolder kmk) throws IOException {
        if (!kmk.children.isEmpty()) {
            JSONArrayWriter kmkuArr = wr.setArray(UPDATABLE_KEY_MANAGEMENT_KEYS_JSON);
            for (KeyManagementKeyUpdateHolder child : kmk.children) {
                JSONObjectWriter kmkuObject = kmkuArr.setObject();
                kmkuObject.setPublicKey(child.keyManagementKey, AlgorithmPreferences.JOSE_ACCEPT_PREFER);
                kmkuObject.setBinary(AUTHORIZATION_JSON, child.authorization);
                scanForUpdatedKeys(kmkuObject, child);
            }
        }
    }


    String serverSessionId;

    ECPublicKey serverEphemeralKey;

    int sessionLifeTime;

    short sessionKeyLimit;

    @Override
    void writeServerRequest(JSONObjectWriter wr) throws IOException {
        //////////////////////////////////////////////////////////////////////////
        // Core session properties
        //////////////////////////////////////////////////////////////////////////
        wr.setString(SERVER_SESSION_ID_JSON, serverSessionId);

        wr.setString(SERVER_TIME_JSON, serverState.serverTime);

        wr.setString(SESSION_KEY_ALGORITHM_JSON, serverState.provisioningSessionAlgorithm);

        wr.setInt(SESSION_KEY_LIMIT_JSON, sessionKeyLimit);

        wr.setInt(SESSION_LIFE_TIME_JSON, sessionLifeTime);

        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.setObject(SERVER_EPHEMERAL_KEY_JSON,
                     JSONObjectWriter.createCorePublicKey(serverEphemeralKey, 
                                                          AlgorithmPreferences.JOSE_ACCEPT_PREFER));

        ////////////////////////////////////////////////////////////////////////
        // Optional key management key
        ////////////////////////////////////////////////////////////////////////
        if (kmkRoot != null) {
            wr.setObject(KEY_MANAGEMENT_KEY_JSON,
                         JSONObjectWriter.createCorePublicKey(kmkRoot.keyManagementKey, 
                                                              AlgorithmPreferences.JOSE_ACCEPT_PREFER));
            scanForUpdatedKeys(wr, kmkRoot);
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.PROVISIONING_INITIALIZATION_REQUEST.getName();
    }
}
