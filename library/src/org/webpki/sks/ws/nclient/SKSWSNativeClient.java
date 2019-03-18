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
package org.webpki.sks.ws.nclient;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.Extension;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyData;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.sks.ws.TrustedGUIAuthorization;
import org.webpki.sks.ws.WSSpecific;

public class SKSWSNativeClient implements SecureKeyStore, WSSpecific {
    @Override
    native public ProvisioningSession createProvisioningSession(String algorithm,
                                                                boolean privacy_enabled,
                                                                String serverSessionId,
                                                                ECPublicKey server_ephemeral_key,
                                                                String issuer_uri,
                                                                PublicKey keyManagementKey,
                                                                int clientTime,
                                                                int sessionLifeTime,
                                                                short sessionKeyLimit) throws SKSException;

    @Override
    native public byte[] closeProvisioningSession(int provisioning_handle,
                                                  byte[] nonce,
                                                  byte[] mac) throws SKSException;

    @Override
    native public EnumeratedProvisioningSession enumerateProvisioningSessions(int provisioning_handle,
                                                                              boolean provisioning_state) throws SKSException;

    @Override
    native public byte[] signProvisioningSessionData(int provisioning_handle,
                                                     byte[] data) throws SKSException;

    @Override
    native public KeyData createKeyEntry(int provisioning_handle,
                                         String id,
                                         String algorithm,
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
                                         byte[] mac) throws SKSException;

    @Override
    native public int getKeyHandle(int provisioning_handle,
                                   String id) throws SKSException;

    @Override
    native public void abortProvisioningSession(int provisioning_handle) throws SKSException;

    @Override
    native public void setCertificatePath(int keyHandle,
                                          X509Certificate[] certificatePath,
                                          byte[] mac) throws SKSException;

    @Override
    native public void addExtension(int keyHandle,
                                    String type,
                                    byte subType,
                                    String qualifier,
                                    byte[] extension_data,
                                    byte[] mac) throws SKSException;

    @Override
    native public void importSymmetricKey(int keyHandle,
                                          byte[] symmetricKey,
                                          byte[] mac) throws SKSException;

    @Override
    native public void importPrivateKey(int keyHandle,
                                        byte[] privateKey,
                                        byte[] mac) throws SKSException;

    @Override
    native public int createPinPolicy(int provisioning_handle,
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
                                      byte[] mac) throws SKSException;

    @Override
    native public int createPukPolicy(int provisioning_handle,
                                      String id,
                                      byte[] puk_value,
                                      byte format,
                                      short retryLimit,
                                      byte[] mac) throws SKSException;

    @Override
    native public void postDeleteKey(int provisioning_handle,
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void postUnlockKey(int provisioning_handle,
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void postUpdateKey(int keyHandle,
                                     int target_key_handle,
                                     byte[] authorization,
                                     byte[] mac) throws SKSException;

    @Override
    native public void postCloneKeyProtection(int keyHandle,
                                              int target_key_handle,
                                              byte[] authorization,
                                              byte[] mac) throws SKSException;

    @Override
    native public KeyAttributes getKeyAttributes(int keyHandle) throws SKSException;

    @Override
    native public EnumeratedKey enumerateKeys(int keyHandle) throws SKSException;

    @Override
    native public byte[] signHashedData(int keyHandle,
                                        String algorithm,
                                        byte[] parameters,
                                        byte[] authorization,
                                        byte[] data) throws SKSException;

    @Override
    native public byte[] performHmac(int keyHandle,
                                     String algorithm,
                                     byte[] parameters,
                                     byte[] authorization,
                                     byte[] data) throws SKSException;

    @Override
    native public byte[] symmetricKeyEncrypt(int keyHandle,
                                             String algorithm,
                                             boolean mode,
                                             byte[] parameters,
                                             byte[] authorization,
                                             byte[] data) throws SKSException;

    @Override
    native public byte[] asymmetricKeyDecrypt(int keyHandle,
                                              String algorithm,
                                              byte[] parameters,
                                              byte[] authorization,
                                              byte[] data) throws SKSException;

    @Override
    native public byte[] keyAgreement(int keyHandle,
                                      String algorithm,
                                      byte[] parameters,
                                      byte[] authorization,
                                      ECPublicKey publicKey) throws SKSException;

    @Override
    native public void deleteKey(int keyHandle,
                                 byte[] authorization) throws SKSException;

    @Override
    native public DeviceInfo getDeviceInfo() throws SKSException;

    @Override
    native public Extension getExtension(int keyHandle,
                                         String type) throws SKSException;

    @Override
    native public KeyProtectionInfo getKeyProtectionInfo(int keyHandle) throws SKSException;

    @Override
    native public void setProperty(int keyHandle,
                                   String type,
                                   String name,
                                   String value) throws SKSException;

    @Override
    native public void unlockKey(int keyHandle,
                                 byte[] authorization) throws SKSException;

    @Override
    native public void changePin(int keyHandle,
                                 byte[] authorization,
                                 byte[] new_pin) throws SKSException;

    @Override
    native public void setPin(int keyHandle,
                              byte[] authorization,
                              byte[] new_pin) throws SKSException;

    @Override
    native public byte[] exportKey(int keyHandle,
                                   byte[] authorization) throws SKSException;

    @Override
    native public String getVersion();

    @Override
    native public void logEvent(String event);

    @Override
    public boolean setTrustedGUIAuthorizationProvider(TrustedGUIAuthorization tga) {
        return false;
    }

    @Override
    public String[] listDevices() throws SKSException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void setDeviceID(String deviceId) {
        // TODO Auto-generated method stub

    }

    @Override
    public String updateFirmware(byte[] chunk) throws SKSException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void updateKeyManagementKey(int provisioning_handle, PublicKey key_managegent_key, byte[] authorization) throws SKSException {
        // TODO Auto-generated method stub

    }

}
