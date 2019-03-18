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
package org.webpki.sks.ws.client;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.security.spec.X509EncodedKeySpec;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.xml.ws.Holder;

import javax.xml.ws.BindingProvider;

import org.webpki.crypto.CertificateUtil;

import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.Extension;
import org.webpki.sks.InputMethod;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyData;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.sks.ws.TrustedGUIAuthorization;
import org.webpki.sks.ws.WSSpecific;
import org.webpki.sks.ws.WSDeviceInfo;

public class SKSWSClient implements SecureKeyStore, WSSpecific {
    public static final String DEFAULT_URL_PROPERTY = "org.webpki.sks.ws.client.url";

    static final byte[] EC_OID = {0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01};

    private SKSWSProxy proxy;

    private String port;

    private TrustedGUIAuthorization tga_provider;

    private String deviceId;

    private class AuthorizationHolder {
        byte[] value;

        AuthorizationHolder(byte[] authorization) {
            value = authorization;
        }
    }

    boolean getTrustedGUIAuthorization(int keyHandle,
                                       AuthorizationHolder authorization_holder,
                                       boolean auth_error) throws SKSException {
        if (tga_provider == null) {
            return false;
        }

        KeyProtectionInfo kpi = getKeyProtectionInfo(keyHandle);
        if (kpi.hasLocalPinProtection()) {
            if (kpi.getPinInputMethod() == InputMethod.TRUSTED_GUI) {
                if (authorization_holder.value != null) {
                    throw new SKSException("Redundant \"Authorization\"", SKSException.ERROR_AUTHORIZATION);
                }
            } else if (kpi.getPinInputMethod() == InputMethod.PROGRAMMATIC || authorization_holder.value != null) {
                return false;
            }
            KeyAttributes ka = getKeyAttributes(keyHandle);
            authorization_holder.value = tga_provider.getTrustedAuthorization(kpi.getPinFormat(),
                    kpi.getPinGrouping(),
                    ka.getAppUsage(),
                    ka.getFriendlyName());
            return authorization_holder.value != null;
        }
        return false;
    }


    public SKSWSClient(String port) {
        this.port = port;
    }

    public SKSWSClient() {
        this(System.getProperty(DEFAULT_URL_PROPERTY));
    }

    private PublicKey createPublicKeyFromBlob(byte[] blob) throws GeneralSecurityException {
        boolean ec_flag = false;
        for (int j = 4; j < 11; j++) {
            ec_flag = true;
            for (int i = 0; i < EC_OID.length; i++) {
                if (blob[j + i] != EC_OID[i]) {
                    ec_flag = false;
                }
            }
            if (ec_flag) break;
        }
        return KeyFactory.getInstance(ec_flag ? "EC" : "RSA").generatePublic(new X509EncodedKeySpec(blob));
    }

    private X509Certificate[] getCertArrayFromBlobs(List<byte[]> blobs) throws IOException {
        Vector<X509Certificate> certs = new Vector<X509Certificate>();
        for (byte[] bcert : blobs) {
            certs.add(CertificateUtil.getCertificateFromBlob(bcert));
        }
        return certs.toArray(new X509Certificate[0]);
    }

    private ECPublicKey getECPublicKey(byte[] blob) throws GeneralSecurityException {
        PublicKey publicKey = createPublicKeyFromBlob(blob);
        if (publicKey instanceof ECPublicKey) {
            return (ECPublicKey) publicKey;
        }
        throw new GeneralSecurityException("Expected EC key");
    }

    /**
     * Factory method. Each WS call should use this method.
     *
     * @return A handle to a shared WS instance
     */
    private SKSWSProxy getSKSWS() {
        if (proxy == null) {
            synchronized (this) {
                SKSWS service = new SKSWS();
                SKSWSProxy temp_proxy = service.getSKSWSPort();
                if (port != null && port.length() > 0) {
                    Map<String, Object> request_object = ((BindingProvider) temp_proxy).getRequestContext();
                    request_object.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, port);
                }
                proxy = temp_proxy;
            }
        }
        return proxy;
    }

    @Override
    public WSDeviceInfo getDeviceInfo() throws SKSException {
        try {
            Holder<Short> api_level = new Holder<Short>();
            Holder<Byte> device_type = new Holder<Byte>();
            Holder<String> update_url = new Holder<String>();
            Holder<String> vendor_name = new Holder<String>();
            Holder<String> vendor_description = new Holder<String>();
            Holder<List<byte[]>> certificatePath = new Holder<List<byte[]>>();
            Holder<List<String>> supported_algorithms = new Holder<List<String>>();
            Holder<Integer> crypto_data_size = new Holder<Integer>();
            Holder<Integer> extension_data_size = new Holder<Integer>();
            Holder<Boolean> device_pin_support = new Holder<Boolean>();
            Holder<Boolean> biometric_support = new Holder<Boolean>();
            Holder<String> connection_port = new Holder<String>();
            getSKSWS().getDeviceInfo(deviceId,
                    api_level,
                    device_type,
                    update_url,
                    vendor_name,
                    vendor_description,
                    certificatePath,
                    supported_algorithms,
                    crypto_data_size,
                    extension_data_size,
                    device_pin_support,
                    biometric_support,
                    connection_port);
            WSDeviceInfo device_info = new WSDeviceInfo(api_level.value,
                    device_type.value,
                    update_url.value,
                    vendor_name.value,
                    vendor_description.value,
                    getCertArrayFromBlobs(certificatePath.value),
                    supported_algorithms.value.toArray(new String[0]),
                    crypto_data_size.value,
                    extension_data_size.value,
                    device_pin_support.value,
                    biometric_support.value,
                    connection_port.value);
            return device_info;
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        } catch (IOException e) {
            throw new SKSException(e);
        }
    }

    @Override
    public ProvisioningSession createProvisioningSession(String session_key_algorithm,
                                                         boolean privacy_enabled,
                                                         String serverSessionId,
                                                         ECPublicKey server_ephemeral_key,
                                                         String issuer_uri,
                                                         PublicKey keyManagementKey,
                                                         int clientTime,
                                                         int sessionLifeTime,
                                                         short sessionKeyLimit) throws SKSException {
        try {
            Holder<String> clientSessionId = new Holder<String>();
            Holder<byte[]> client_ephemeral_key = new Holder<byte[]>();
            Holder<byte[]> session_attestation = new Holder<byte[]>();
            int provisioning_handle = getSKSWS().createProvisioningSession(deviceId,
                    session_key_algorithm,
                    privacy_enabled,
                    serverSessionId,
                    server_ephemeral_key.getEncoded(),
                    issuer_uri,
                    keyManagementKey == null ? null : keyManagementKey.getEncoded(),
                    clientTime,
                    sessionLifeTime,
                    sessionKeyLimit,
                    clientSessionId,
                    client_ephemeral_key,
                    session_attestation);
            return new ProvisioningSession(provisioning_handle,
                    clientSessionId.value,
                    session_attestation.value,
                    getECPublicKey(client_ephemeral_key.value));
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        } catch (GeneralSecurityException e) {
            throw new SKSException(e);
        }
    }


    @Override
    public byte[] closeProvisioningSession(int provisioning_handle,
                                           byte[] challenge,
                                           byte[] mac) throws SKSException {
        try {
            return getSKSWS().closeProvisioningSession(deviceId,
                    provisioning_handle,
                    challenge,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public EnumeratedProvisioningSession enumerateProvisioningSessions(int provisioning_handle, boolean provisioning_state) throws SKSException {
        try {
            Holder<String> session_key_algorithm = new Holder<String>();
            Holder<Boolean> privacy_enabled = new Holder<Boolean>();
            Holder<byte[]> keyManagementKey = new Holder<byte[]>();
            Holder<Integer> clientTime = new Holder<Integer>();
            Holder<Integer> sessionLifeTime = new Holder<Integer>();
            Holder<String> serverSessionId = new Holder<String>();
            Holder<String> clientSessionId = new Holder<String>();
            Holder<String> issuer_uri = new Holder<String>();
            provisioning_handle = getSKSWS().enumerateProvisioningSessions(deviceId,
                    provisioning_handle,
                    provisioning_state,
                    session_key_algorithm,
                    privacy_enabled,
                    keyManagementKey,
                    clientTime,
                    sessionLifeTime,
                    serverSessionId,
                    clientSessionId,
                    issuer_uri);
            return provisioning_handle == EnumeratedProvisioningSession.INIT_ENUMERATION ?
                    null : new EnumeratedProvisioningSession(provisioning_handle,
                    session_key_algorithm.value,
                    privacy_enabled.value,
                    keyManagementKey.value == null ? null : createPublicKeyFromBlob(keyManagementKey.value),
                    clientTime.value,
                    sessionLifeTime.value,
                    serverSessionId.value,
                    clientSessionId.value,
                    issuer_uri.value);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        } catch (GeneralSecurityException e) {
            throw new SKSException(e);
        }
    }

    @Override
    public void abortProvisioningSession(int provisioning_handle) throws SKSException {
        try {
            getSKSWS().abortProvisioningSession(deviceId,
                    provisioning_handle);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public byte[] signProvisioningSessionData(int provisioning_handle,
                                              byte[] data) throws SKSException {
        try {
            return getSKSWS().signProvisioningSessionData(deviceId,
                    provisioning_handle,
                    data);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public int createPukPolicy(int provisioning_handle,
                               String id,
                               byte[] encrypted_puk,
                               byte format,
                               short retryLimit,
                               byte[] mac) throws SKSException {
        try {
            return getSKSWS().createPukPolicy(deviceId,
                    provisioning_handle,
                    id,
                    encrypted_puk,
                    format,
                    retryLimit,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public int createPinPolicy(int provisioning_handle,
                               String id,
                               int puk_policy_handle,
                               boolean userDefined,
                               boolean userModifiable,
                               byte format,
                               short retryLimit,
                               byte grouping,
                               byte patternRestrictions,
                               short minLength,
                               short maxLength,
                               byte inputMethod,
                               byte[] mac) throws SKSException {
        try {
            return getSKSWS().createPinPolicy(deviceId,
                    provisioning_handle,
                    id,
                    puk_policy_handle,
                    userDefined,
                    userModifiable,
                    format,
                    retryLimit,
                    grouping,
                    patternRestrictions,
                    minLength,
                    maxLength,
                    inputMethod,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public KeyData createKeyEntry(int provisioning_handle,
                                  String id,
                                  String key_entry_algorithm,
                                  byte[] serverSeed,
                                  boolean devicePinProtection,
                                  int pin_policy_handle,
                                  byte[] pin_value,
                                  boolean enablePinCaching,
                                  byte biometricProtection,
                                  byte exportProtection,
                                  byte deleteProtection,
                                  byte appUsage,
                                  String friendlyName,
                                  String key_algorithm,
                                  byte[] keyParameters,
                                  String[] endorsedAlgorithms,
                                  byte[] mac) throws SKSException {
        try {
            Holder<byte[]> publicKey = new Holder<byte[]>();
            Holder<byte[]> key_attestation = new Holder<byte[]>();
            List<String> lalg = new ArrayList<String>();
            for (String alg : endorsedAlgorithms) {
                lalg.add(alg);
            }
            int keyHandle = getSKSWS().createKeyEntry(deviceId,
                    provisioning_handle,
                    id,
                    key_entry_algorithm,
                    serverSeed,
                    devicePinProtection,
                    pin_policy_handle,
                    pin_value,
                    enablePinCaching,
                    biometricProtection,
                    exportProtection,
                    deleteProtection,
                    appUsage,
                    friendlyName,
                    key_algorithm,
                    keyParameters,
                    lalg,
                    mac,
                    publicKey,
                    key_attestation);
            return new KeyData(keyHandle,
                    createPublicKeyFromBlob(publicKey.value),
                    key_attestation.value);
        } catch (GeneralSecurityException e) {
            throw new SKSException(e);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public int getKeyHandle(int provisioning_handle,
                            String id) throws SKSException {
        try {
            return getSKSWS().getKeyHandle(deviceId,
                    provisioning_handle,
                    id);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void setCertificatePath(int keyHandle,
                                   X509Certificate[] certificatePath,
                                   byte[] mac) throws SKSException {
        try {
            List<byte[]> lcert_path = new ArrayList<byte[]>();
            for (X509Certificate cert : certificatePath) {
                lcert_path.add(cert.getEncoded());
            }
            getSKSWS().setCertificatePath(deviceId,
                    keyHandle,
                    lcert_path,
                    mac);
        } catch (GeneralSecurityException e) {
            throw new SKSException(e);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void importSymmetricKey(int keyHandle,
                                   byte[] encrypted_key,
                                   byte[] mac) throws SKSException {
        try {
            getSKSWS().importSymmetricKey(deviceId,
                    keyHandle,
                    encrypted_key,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void addExtension(int keyHandle,
                             String type,
                             byte subType,
                             String qualifier,
                             byte[] extension_data,
                             byte[] mac) throws SKSException {
        try {
            getSKSWS().addExtension(deviceId,
                    keyHandle,
                    type,
                    subType,
                    qualifier,
                    extension_data,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void importPrivateKey(int keyHandle,
                                 byte[] encrypted_key,
                                 byte[] mac) throws SKSException {
        try {
            getSKSWS().importPrivateKey(deviceId,
                    keyHandle,
                    encrypted_key,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void postDeleteKey(int provisioning_handle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException {
        try {
            getSKSWS().postDeleteKey(deviceId,
                    provisioning_handle,
                    target_key_handle,
                    authorization,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void postUnlockKey(int provisioning_handle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException {
        try {
            getSKSWS().postUnlockKey(deviceId,
                    provisioning_handle,
                    target_key_handle,
                    authorization,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void postUpdateKey(int keyHandle,
                              int target_key_handle,
                              byte[] authorization,
                              byte[] mac) throws SKSException {
        try {
            getSKSWS().postUpdateKey(deviceId,
                    keyHandle,
                    target_key_handle,
                    authorization,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void postCloneKeyProtection(int keyHandle,
                                       int target_key_handle,
                                       byte[] authorization,
                                       byte[] mac) throws SKSException {
        try {
            getSKSWS().postCloneKeyProtection(deviceId,
                    keyHandle,
                    target_key_handle,
                    authorization,
                    mac);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public EnumeratedKey enumerateKeys(int keyHandle) throws SKSException {
        try {
            Holder<Integer> provisioning_handle = new Holder<Integer>();
            keyHandle = getSKSWS().enumerateKeys(deviceId, keyHandle, provisioning_handle);
            return keyHandle == EnumeratedKey.INIT_ENUMERATION ? null : new EnumeratedKey(keyHandle, provisioning_handle.value);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public KeyAttributes getKeyAttributes(int keyHandle) throws SKSException {
        try {
            Holder<Short> symmetric_key_length = new Holder<Short>();
            Holder<List<byte[]>> certificatePath = new Holder<List<byte[]>>();
            Holder<Byte> appUsage = new Holder<Byte>();
            Holder<String> friendlyName = new Holder<String>();
            Holder<List<String>> endorsedAlgorithms = new Holder<List<String>>();
            Holder<List<String>> extension_types = new Holder<List<String>>();
            getSKSWS().getKeyAttributes(deviceId,
                    keyHandle,
                    symmetric_key_length,
                    certificatePath,
                    appUsage,
                    friendlyName,
                    endorsedAlgorithms,
                    extension_types);
            return new KeyAttributes(symmetric_key_length.value,
                    getCertArrayFromBlobs(certificatePath.value),
                    appUsage.value,
                    friendlyName.value,
                    endorsedAlgorithms.value.toArray(new String[0]),
                    extension_types.value.toArray(new String[0]));
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        } catch (IOException e) {
            throw new SKSException(e);
        }
    }

    @Override
    public KeyProtectionInfo getKeyProtectionInfo(int keyHandle) throws SKSException {
        try {
            Holder<Byte> protectionStatus = new Holder<Byte>();
            Holder<Byte> puk_format = new Holder<Byte>();
            Holder<Short> puk_retry_limit = new Holder<Short>();
            Holder<Short> puk_error_count = new Holder<Short>();
            Holder<Boolean> userDefined = new Holder<Boolean>();
            Holder<Boolean> userModifiable = new Holder<Boolean>();
            Holder<Byte> format = new Holder<Byte>();
            Holder<Short> retryLimit = new Holder<Short>();
            Holder<Byte> grouping = new Holder<Byte>();
            Holder<Byte> patternRestrictions = new Holder<Byte>();
            Holder<Short> minLength = new Holder<Short>();
            Holder<Short> maxLength = new Holder<Short>();
            Holder<Byte> inputMethod = new Holder<Byte>();
            Holder<Short> pin_error_count = new Holder<Short>();
            Holder<Boolean> enablePinCaching = new Holder<Boolean>();
            Holder<Byte> biometricProtection = new Holder<Byte>();
            Holder<Byte> exportProtection = new Holder<Byte>();
            Holder<Byte> deleteProtection = new Holder<Byte>();
            Holder<Byte> key_backup = new Holder<Byte>();
            getSKSWS().getKeyProtectionInfo(deviceId,
                    keyHandle,
                    protectionStatus,
                    puk_format,
                    puk_retry_limit,
                    puk_error_count,
                    userDefined,
                    userModifiable,
                    format,
                    retryLimit,
                    grouping,
                    patternRestrictions,
                    minLength,
                    maxLength,
                    inputMethod,
                    pin_error_count,
                    enablePinCaching,
                    biometricProtection,
                    exportProtection,
                    deleteProtection,
                    key_backup);
            return new KeyProtectionInfo(protectionStatus.value,
                    puk_format.value,
                    puk_retry_limit.value,
                    puk_error_count.value,
                    userDefined.value,
                    userModifiable.value,
                    format.value,
                    retryLimit.value,
                    grouping.value,
                    patternRestrictions.value,
                    minLength.value,
                    maxLength.value,
                    inputMethod.value,
                    pin_error_count.value,
                    enablePinCaching.value,
                    biometricProtection.value,
                    exportProtection.value,
                    deleteProtection.value,
                    key_backup.value);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void updateKeyManagementKey(int provisioning_handle,
                                       PublicKey key_managegent_key,
                                       byte[] authorization) throws SKSException {
        try {
            getSKSWS().updateKeyManagementKey(deviceId,
                    provisioning_handle,
                    key_managegent_key.getEncoded(),
                    authorization);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public Extension getExtension(int keyHandle,
                                  String type) throws SKSException {
        try {
            Holder<Byte> subType = new Holder<Byte>();
            Holder<String> qualifier = new Holder<String>();
            Holder<byte[]> extension_data = new Holder<byte[]>();
            getSKSWS().getExtension(deviceId,
                    keyHandle,
                    type,
                    subType,
                    qualifier,
                    extension_data);
            return new Extension(subType.value,
                    qualifier.value,
                    extension_data.value);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void setProperty(int keyHandle,
                            String type,
                            String name,
                            String value) throws SKSException {
        try {
            getSKSWS().setProperty(deviceId,
                    keyHandle,
                    type,
                    name,
                    value);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void deleteKey(int keyHandle,
                          byte[] authorization) throws SKSException {
        try {
            getSKSWS().deleteKey(deviceId,
                    keyHandle,
                    authorization);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public byte[] exportKey(int keyHandle,
                            byte[] authorization) throws SKSException {
        try {
            return getSKSWS().exportKey(deviceId,
                    keyHandle,
                    authorization);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void unlockKey(int keyHandle,
                          byte[] authorization) throws SKSException {
        try {
            getSKSWS().unlockKey(deviceId,
                    keyHandle,
                    authorization);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void changePin(int keyHandle,
                          byte[] authorization,
                          byte[] new_pin) throws SKSException {
        try {
            getSKSWS().changePin(deviceId,
                    keyHandle,
                    authorization,
                    new_pin);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public void setPin(int keyHandle,
                       byte[] authorization,
                       byte[] new_pin) throws SKSException {
        try {
            getSKSWS().setPin(deviceId,
                    keyHandle,
                    authorization,
                    new_pin);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public byte[] signHashedData(int keyHandle,
                                 String algorithm,
                                 byte[] parameters,
                                 byte[] authorization,
                                 byte[] data) throws SKSException {
        boolean tga = false;
        while (true) {
            try {
                AuthorizationHolder auth = new AuthorizationHolder(authorization);
                tga = getTrustedGUIAuthorization(keyHandle, auth, tga);
                return getSKSWS().signHashedData(deviceId,
                        keyHandle,
                        algorithm,
                        parameters,
                        tga,
                        auth.value,
                        data);
            } catch (SKSException_Exception e) {
                if (!tga || (e.getFaultInfo().getError() != SKSException.ERROR_AUTHORIZATION)) {
                    throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
                }
                authorization = null;
            }
        }
    }

    @Override
    public byte[] asymmetricKeyDecrypt(int keyHandle,
                                       String algorithm,
                                       byte[] parameters,
                                       byte[] authorization,
                                       byte[] data) throws SKSException {
        boolean tga = false;
        while (true) {
            try {
                AuthorizationHolder auth = new AuthorizationHolder(authorization);
                tga = getTrustedGUIAuthorization(keyHandle, auth, tga);
                return getSKSWS().asymmetricKeyDecrypt(deviceId,
                        keyHandle,
                        algorithm,
                        parameters,
                        tga,
                        auth.value,
                        data);
            } catch (SKSException_Exception e) {
                if (!tga || (e.getFaultInfo().getError() != SKSException.ERROR_AUTHORIZATION)) {
                    throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
                }
                authorization = null;
            }
        }
    }

    @Override
    public byte[] keyAgreement(int keyHandle,
                               String algorithm,
                               byte[] parameters,
                               byte[] authorization,
                               ECPublicKey publicKey) throws SKSException {
        boolean tga = false;
        while (true) {
            try {
                AuthorizationHolder auth = new AuthorizationHolder(authorization);
                tga = getTrustedGUIAuthorization(keyHandle, auth, tga);
                return getSKSWS().keyAgreement(deviceId,
                        keyHandle,
                        algorithm,
                        parameters,
                        tga,
                        auth.value,
                        publicKey.getEncoded());
            } catch (SKSException_Exception e) {
                if (!tga || (e.getFaultInfo().getError() != SKSException.ERROR_AUTHORIZATION)) {
                    throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
                }
                authorization = null;
            }
        }
    }

    @Override
    public byte[] performHmac(int keyHandle,
                              String algorithm,
                              byte[] parameters,
                              byte[] authorization,
                              byte[] data) throws SKSException {
        boolean tga = false;
        while (true) {
            try {
                AuthorizationHolder auth = new AuthorizationHolder(authorization);
                tga = getTrustedGUIAuthorization(keyHandle, auth, tga);
                return getSKSWS().performHmac(deviceId,
                        keyHandle,
                        algorithm,
                        parameters,
                        tga,
                        auth.value,
                        data);
            } catch (SKSException_Exception e) {
                if (!tga || (e.getFaultInfo().getError() != SKSException.ERROR_AUTHORIZATION)) {
                    throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
                }
                authorization = null;
            }
        }
    }

    @Override
    public byte[] symmetricKeyEncrypt(int keyHandle,
                                      String algorithm,
                                      boolean mode,
                                      byte[] parameters,
                                      byte[] authorization,
                                      byte[] data) throws SKSException {
        boolean tga = false;
        while (true) {
            try {
                AuthorizationHolder auth = new AuthorizationHolder(authorization);
                tga = getTrustedGUIAuthorization(keyHandle, auth, tga);
                return getSKSWS().symmetricKeyEncrypt(deviceId,
                        keyHandle,
                        algorithm,
                        mode,
                        parameters,
                        tga,
                        auth.value,
                        data);
            } catch (SKSException_Exception e) {
                if (!tga || (e.getFaultInfo().getError() != SKSException.ERROR_AUTHORIZATION)) {
                    throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
                }
                authorization = null;
            }
        }
    }

    @Override
    public String updateFirmware(byte[] chunk) throws SKSException {
        try {
            return getSKSWS().updateFirmware(deviceId,
                    chunk);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public String[] listDevices() throws SKSException {
        try {
            return getSKSWS().listDevices().toArray(new String[0]);
        } catch (SKSException_Exception e) {
            throw new SKSException(e.getFaultInfo().getMessage(), e.getFaultInfo().getError());
        }
    }

    @Override
    public String getVersion() {
        return getSKSWS().getVersion();
    }

    @Override
    public void logEvent(String event) {
        getSKSWS().logEvent(event);
    }

    @Override
    public boolean setTrustedGUIAuthorizationProvider(TrustedGUIAuthorization tga_provider) {
        this.tga_provider = tga_provider;
        return true;
    }

    @Override
    public void setDeviceID(String deviceId) {
        this.deviceId = deviceId;
    }

    /**
     * Test method. Use empty argument list for help.
     *
     * @param args Command line arguments
     * @throws SKSException
     */
    public static void main(String args[]) throws SKSException {
        if (args.length != 1) {
            System.out.println("SKSWSClient port\n if port is set to \"default\" the WSDL value is used\n" +
                    "port may also be set with the JVM -D" + DEFAULT_URL_PROPERTY + "=port");
            System.exit(3);
        }
        SKSWSClient client = args[0].equals("default") ? new SKSWSClient() : new SKSWSClient(args[0]);
        System.out.println("Version=" + client.getVersion() + "\nDevice=" + client.getDeviceInfo().getVendorDescription());
    }
}
