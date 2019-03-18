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
import java.security.cert.X509Certificate;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.CertificateUtil;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;

import org.webpki.keygen2.ServerState.Key;
import org.webpki.keygen2.ServerState.PostOperation;
import org.webpki.keygen2.ServerState.PostProvisioningTargetKey;
import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningFinalizationRequestEncoder extends ServerEncoder {

    private static final long serialVersionUID = 1L;

    ServerState serverState;

    // Constructors

    public ProvisioningFinalizationRequestEncoder(ServerState serverState) throws IOException {
        this.serverState = serverState;
        serverState.checkState(true, serverState.currentPhase == ProtocolPhase.KEY_CREATION ?
                          ProtocolPhase.KEY_CREATION : ProtocolPhase.PROVISIONING_FINALIZATION);
        serverState.currentPhase = ProtocolPhase.PROVISIONING_FINALIZATION;
    }


    byte[] mac(byte[] data, byte[] method) throws IOException, GeneralSecurityException {
        return serverState.mac(data, method);
    }


    void mac(JSONObjectWriter wr, byte[] data, byte[] method) throws IOException, GeneralSecurityException {
        wr.setBinary(MAC_JSON, mac(data, method));
    }


    void writePostOp(JSONObjectWriter wr,
                     PostProvisioningTargetKey targetKey,
                     MacGenerator postOpMac) throws IOException, GeneralSecurityException {
        wr.setBinary(CertificateFilter.CF_FINGER_PRINT, HashAlgorithms.SHA256.digest(targetKey.certificateData));
        wr.setString(SERVER_SESSION_ID_JSON, targetKey.serverSessionId);
        wr.setString(CLIENT_SESSION_ID_JSON, targetKey.clientSessionId);
        byte[] keyId = serverState.serverCryptoInterface.mac(targetKey.certificateData, serverState.getDeviceID());
        byte[] authorization = serverState.serverCryptoInterface.generateKeyManagementAuthorization(targetKey.keyManagementKey,
                ArrayUtil.add(SecureKeyStore.KMK_TARGET_KEY_REFERENCE,
                              keyId));
        wr.setBinary(AUTHORIZATION_JSON, authorization);
        postOpMac.addArray(authorization);
        mac(wr, postOpMac.getResult(), targetKey.postOperation.getMethod());
    }

    void writeExtensions(JSONObjectWriter wr, Key key, byte[] eeCertificate, byte subType) 
    throws IOException, GeneralSecurityException {
        JSONArrayWriter arr = null;
        for (ServerState.ExtensionInterface ei : key.extensions.values()) {
            if (ei.getSubType() == subType) {
                if (arr == null) {
                    arr = wr.setArray(ei.getJSONArrayString());
                }
                MacGenerator addExt = new MacGenerator();
                addExt.addArray(eeCertificate);
                addExt.addString(ei.type);
                addExt.addByte(ei.getSubType());
                addExt.addString(ei.getQualifier());
                addExt.addBlob(ei.getExtensionData());
                ei.writeExtension(arr.setObject(), mac(addExt.getResult(), SecureKeyStore.METHOD_ADD_EXTENSION));
            }
        }
    }

    void issueCredential(JSONObjectWriter wr, Key key) throws IOException, GeneralSecurityException {
        ////////////////////////////////////////////////////////////////////////
        // Always: the ID, X509 Certificate(s) and MAC
        ////////////////////////////////////////////////////////////////////////
        wr.setString(ID_JSON, key.id);

        MacGenerator setCertificate = new MacGenerator();
        setCertificate.addArray(key.publicKey.getEncoded());
        setCertificate.addString(key.id);
        X509Certificate[] certificatePath = key.certificatePath;
        if (key.trustAnchorSet && !CertificateUtil.isTrustAnchor(certificatePath[certificatePath.length - 1])) {
            throw new IOException("Invalid \"" + TRUST_ANCHOR_JSON + "\"");
        }
        for (X509Certificate certificate : certificatePath) {
            setCertificate.addArray(certificate.getEncoded());
        }
        wr.setCertificatePath(certificatePath);
        mac(wr, setCertificate.getResult(), SecureKeyStore.METHOD_SET_CERTIFICATE_PATH);
        byte[] eeCertificate = certificatePath[0].getEncoded();

        ////////////////////////////////////////////////////////////////////////
        // Optional: A certificate path may also contain a TA
        ////////////////////////////////////////////////////////////////////////
        if (key.trustAnchorSet) {
            wr.setBoolean(TRUST_ANCHOR_JSON, key.trustAnchor);
        }

        ////////////////////////////////////////////////////////////////////////
        // Optional: "piggybacked" symmetric key
        ////////////////////////////////////////////////////////////////////////
        if (key.encryptedSymmetricKey != null) {
            MacGenerator setSymkey = new MacGenerator();
            setSymkey.addArray(eeCertificate);
            setSymkey.addArray(key.encryptedSymmetricKey);
            mac(wr.setObject(IMPORT_SYMMETRIC_KEY_JSON).setBinary(ENCRYPTED_KEY_JSON, key.encryptedSymmetricKey),
                    setSymkey.getResult(), SecureKeyStore.METHOD_IMPORT_SYMMETRIC_KEY);
        }

        ////////////////////////////////////////////////////////////////////////
        // Optional: private key
        ////////////////////////////////////////////////////////////////////////
        if (key.encryptedPrivateKey != null) {
            MacGenerator setPrivkey = new MacGenerator();
            setPrivkey.addArray(eeCertificate);
            setPrivkey.addArray(key.encryptedPrivateKey);
            mac(wr.setObject(IMPORT_PRIVATE_KEY_JSON).setBinary(ENCRYPTED_KEY_JSON, key.encryptedPrivateKey),
                    setPrivkey.getResult(), SecureKeyStore.METHOD_IMPORT_PRIVATE_KEY);
        }

        ////////////////////////////////////////////////////////////////////////
        // Optional: property bags, extensions, and logotypes.
        // Note: Order must be followed!
        ////////////////////////////////////////////////////////////////////////
        writeExtensions(wr, key, eeCertificate, SecureKeyStore.SUB_TYPE_EXTENSION);
        writeExtensions(wr, key, eeCertificate, SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION);
        writeExtensions(wr, key, eeCertificate, SecureKeyStore.SUB_TYPE_PROPERTY_BAG);
        writeExtensions(wr, key, eeCertificate, SecureKeyStore.SUB_TYPE_LOGOTYPE);

        ////////////////////////////////////////////////////////////////////////
        // Optional: post operation associated with the provisioned key
        ////////////////////////////////////////////////////////////////////////
        if (key.cloneOrUpdateOperation != null) {
            MacGenerator setPostMac = new MacGenerator();
            setPostMac.addArray(eeCertificate);
            writePostOp(wr.setObject(key.cloneOrUpdateOperation.postOperation.getJSONProp()),
                        key.cloneOrUpdateOperation,
                        setPostMac);
        }
    }

    void optionalPostOps(JSONObjectWriter wr, PostOperation operation) throws IOException, GeneralSecurityException {
        JSONArrayWriter opWriter = null;
        for (ServerState.PostProvisioningTargetKey pptk : serverState.postOperations) {
            if (pptk.postOperation == operation) {
                if (opWriter == null) {
                    opWriter = wr.setArray(operation.getJSONProp());
                }
                writePostOp(opWriter.setObject(), pptk, new MacGenerator());
            }
        }
    }

    @Override
    void writeServerRequest(JSONObjectWriter wr) throws IOException {
        try {
            //////////////////////////////////////////////////////////////////////////
            // Session properties
            //////////////////////////////////////////////////////////////////////////
            wr.setString(SERVER_SESSION_ID_JSON, serverState.serverSessionId);

            wr.setString(CLIENT_SESSION_ID_JSON, serverState.clientSessionId);

            ////////////////////////////////////////////////////////////////////////
            // Write [0..n] Credentials
            ////////////////////////////////////////////////////////////////////////
            if (!serverState.requestedKeys.isEmpty()) {
                JSONArrayWriter keyArray = wr.setArray(ISSUED_CREDENTIALS_JSON);
                for (ServerState.Key key : serverState.getKeys()) {
                    issueCredential(keyArray.setObject(), key);
                }
            }

            ////////////////////////////////////////////////////////////////////////
            // Optional: post provisioning unlock operations
            ////////////////////////////////////////////////////////////////////////
            optionalPostOps(wr, ServerState.PostOperation.UNLOCK_KEY);

            ////////////////////////////////////////////////////////////////////////
            // Optional: post provisioning delete operations
            ////////////////////////////////////////////////////////////////////////
            optionalPostOps(wr, ServerState.PostOperation.DELETE_KEY);

            ////////////////////////////////////////////////////////////////////////
            // Done with the crypto, now set the "closeProvisioningSession" MAC
            ////////////////////////////////////////////////////////////////////////
            MacGenerator close = new MacGenerator();
            close.addString(serverState.clientSessionId);
            close.addString(serverState.serverSessionId);
            close.addString(serverState.issuerUri);
            close.addArray(serverState.savedCloseNonce = serverState.serverCryptoInterface.generateNonce());
            wr.setBinary(NONCE_JSON, serverState.savedCloseNonce);
            wr.setBinary(MAC_JSON, mac(close.getResult(), SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION));
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.PROVISIONING_FINALIZATION_REQUEST.getName();
    }
}
