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

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

/**
 * SKS (Secure Key Store) API.
 */
public interface SecureKeyStore {

    ///////////////////////////////////////////////////////////////////////////////////
    // SKS "sanity" limits
    ///////////////////////////////////////////////////////////////////////////////////
    int MAX_LENGTH_PIN_PUK                    = 128;
    int MAX_LENGTH_QUALIFIER                  = 128;
    int MAX_LENGTH_SYMMETRIC_KEY              = 128;
    int MAX_LENGTH_ID_TYPE                    = 32;
    int MAX_LENGTH_SERVER_SEED                = 64;
    int MAX_LENGTH_URI                        = 1000;
    int MAX_RETRY_LIMIT                       = 10000;
    
    ///////////////////////////////////////////////////////////////////////////////////
    // Method names are used "as is" in MAC operations
    ///////////////////////////////////////////////////////////////////////////////////
    byte[] METHOD_SET_CERTIFICATE_PATH        = {'s','e','t','C','e','r','t','i','f','i','c','a','t','e','P','a','t','h'};
    byte[] METHOD_IMPORT_SYMMETRIC_KEY        = {'i','m','p','o','r','t','S','y','m','m','e','t','r','i','c','K','e','y'};
    byte[] METHOD_IMPORT_PRIVATE_KEY          = {'i','m','p','o','r','t','P','r','i','v','a','t','e','K','e','y'};
    byte[] METHOD_CLOSE_PROVISIONING_SESSION  = {'c','l','o','s','e','P','r','o','v','i','s','i','o','n','i','n','g','S','e','s','s','i','o','n'};
    byte[] METHOD_CREATE_KEY_ENTRY            = {'c','r','e','a','t','e','K','e','y','E','n','t','r','y'};
    byte[] METHOD_CREATE_PIN_POLICY           = {'c','r','e','a','t','e','P','I','N','P','o','l','i','c','y'};
    byte[] METHOD_CREATE_PUK_POLICY           = {'c','r','e','a','t','e','P','U','K','P','o','l','i','c','y'};
    byte[] METHOD_ADD_EXTENSION               = {'a','d','d','E','x','t','e','n','s','i','o','n'};
    byte[] METHOD_POST_DELETE_KEY             = {'p','o','s','t','D','e','l','e','t','e','K','e','y'};
    byte[] METHOD_POST_UNLOCK_KEY             = {'p','o','s','t','U','n','l','o','c','k','K','e','y'};
    byte[] METHOD_POST_UPDATE_KEY             = {'p','o','s','t','U','p','d','a','t','e','K','e','y'};
    byte[] METHOD_POST_CLONE_KEY_PROTECTION   = {'p','o','s','t','C','l','o','n','e','K','e','y','P','r','o','t','e','c','t','i','o','n'};

    ///////////////////////////////////////////////////////////////////////////////////
    // KDF constants that are used "as is" in MAC operations
    ///////////////////////////////////////////////////////////////////////////////////
    byte[] KDF_DEVICE_ATTESTATION             = {'D','e','v','i','c','e','A','t','t','e','s','t','a','t','i','o','n'};
    byte[] KDF_ENCRYPTION_KEY                 = {'E','n','c','r','y','p','t','i','o','n','K','e','y'};
    byte[] KDF_EXTERNAL_SIGNATURE             = {'E','x','t','e','r','n','a','l','S','i','g','n','a','t','u','r','e'};
    byte[] KDF_ANONYMOUS                      = {'A','n','o','n','y','m','o','u','s'};

    ///////////////////////////////////////////////////////////////////////////////////
    // Constants that are used "as is" in KeyManagementKey operations
    ///////////////////////////////////////////////////////////////////////////////////
    byte[] KMK_TARGET_KEY_REFERENCE           = {'T','a','r','g','e','t','K','e','y','R','e','f','e','r','e','n','c','e'};
    byte[] KMK_ROLL_OVER_AUTHORIZATION        = {'R','o','l','l','O','v','e','r','A','u','t','h','o','r','i','z','a','t','i','o','n'};

    ///////////////////////////////////////////////////////////////////////////////////
    // Predefined PIN and PUK policy IDs for MAC operations
    ///////////////////////////////////////////////////////////////////////////////////
    String CRYPTO_STRING_NOT_AVAILABLE        = "";

    ///////////////////////////////////////////////////////////////////////////////////
    // SKS variable names. For provisioning most of them are the same in KeyGen2
    ///////////////////////////////////////////////////////////////////////////////////
    String VAR_APP_USAGE                      = "appUsage";
    String VAR_ATTESTATION                    = "attestation";
    String VAR_AUTHORIZATION                  = "authorization";
    String VAR_BIOMETRIC_PROTECTION           = "biometricProtection";
    String VAR_CLIENT_EPHEMERAL_KEY           = "clientEphemeralKey";
    String VAR_CLIENT_SESSION_ID              = "clientSessionId";
    String VAR_CLIENT_TIME                    = "clientTime";
    String VAR_CRYPTO_DATA_SIZE               = "cryptoDataSize";
    String VAR_DATA                           = "data";
    String VAR_EXTENSION_DATA                 = "extensionData";
    String VAR_DELETE_PROTECTION              = "deleteProtection";
    String VAR_DEVICE_PIN_PROTECTION          = "devicePinProtection";
    String VAR_ENDORSED_ALGORITHMS            = "endorsedAlgorithms";
    String VAR_ENABLE_PIN_CACHING             = "enablePinCaching";
    String VAR_ENCRYPTED_KEY                  = "encryptedKey";
    String VAR_ENCRYPTED_PUK                  = "encryptedPuk";
    String VAR_EXPORT_PROTECTION              = "exportProtection";
    String VAR_FORMAT                         = "format";
    String VAR_FRIENDLY_NAME                  = "friendlyName";
    String VAR_GROUPING                       = "grouping";
    String VAR_ID                             = "id";
    String VAR_INPUT_METHOD                   = "inputMethod";
    String VAR_ISSUER_URI                     = "issuerUri";
    String VAR_KEY_ALGORITHM                  = "keyAlgorithm";
    String VAR_KEY_ENTRY_ALGORITHM            = "keyEntryAlgorithm";       
    String VAR_KEY_MANAGEMENT_KEY             = "keyManagementKey";
    String VAR_KEY_PARAMETERS                 = "keyParameters";
    String VAR_MAC                            = "mac";
    String VAR_MAX_LENGTH                     = "maxLength";
    String VAR_MIN_LENGTH                     = "minLength";
    String VAR_NAME                           = "name";
    String VAR_NONCE                          = "nonce";
    String VAR_PARAMETERS                     = "parameters";
    String VAR_PATTERN_RESTRICTIONS           = "patternRestrictions";
    String VAR_PIN_VALUE                      = "pinValue";
    String VAR_PRIVACY_ENABLED                = "privacyEnabled";
    String VAR_PROPERTY                       = "property";
    String VAR_PROPERTY_BAG                   = "propertyBag";
    String VAR_PUBLIC_KEY                     = "publicKey";
    String VAR_QUALIFIER                      = "qualifier";
    String VAR_RETRY_LIMIT                    = "retryLimit";
    String VAR_SERVER_EPHEMERAL_KEY           = "serverEphemeralKey";
    String VAR_SERVER_SEED                    = "serverSeed";
    String VAR_SERVER_SESSION_ID              = "serverSessionId";
    String VAR_SERVER_TIME                    = "serverTime";
    String VAR_SESSION_KEY_ALGORITHM          = "sessionKeyAlgorithm";
    String VAR_SESSION_KEY_LIMIT              = "sessionKeyLimit";
    String VAR_SESSION_LIFE_TIME              = "sessionLifeTime";
    String VAR_SUB_TYPE                       = "subType";
    String VAR_TYPE                           = "type";
    String VAR_USER_MODIFIABLE                = "userModifiable";
    String VAR_VALUE                          = "value";
    String VAR_WRITABLE                       = "writable";

    ///////////////////////////////////////////////////////////////////////////////////
    // See "AppUsage" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    byte APP_USAGE_SIGNATURE                  = 0x00;
    byte APP_USAGE_AUTHENTICATION             = 0x01;
    byte APP_USAGE_ENCRYPTION                 = 0x02;
    byte APP_USAGE_UNIVERSAL                  = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // See "PIN Grouping" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    byte PIN_GROUPING_NONE                    = 0x00;
    byte PIN_GROUPING_SHARED                  = 0x01;
    byte PIN_GROUPING_SIGN_PLUS_STD           = 0x02;
    byte PIN_GROUPING_UNIQUE                  = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // See "PIN Pattern Control" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    byte PIN_PATTERN_TWO_IN_A_ROW             = 0x01;
    byte PIN_PATTERN_THREE_IN_A_ROW           = 0x02;
    byte PIN_PATTERN_SEQUENCE                 = 0x04;
    byte PIN_PATTERN_REPEATED                 = 0x08;
    byte PIN_PATTERN_MISSING_GROUP            = 0x10;

    ///////////////////////////////////////////////////////////////////////////////////
    // See "PIN and PUK Formats" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    byte PASSPHRASE_FORMAT_NUMERIC            = 0x00;
    byte PASSPHRASE_FORMAT_ALPHANUMERIC       = 0x01;
    byte PASSPHRASE_FORMAT_STRING             = 0x02;
    byte PASSPHRASE_FORMAT_BINARY             = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // See "SubType" for "addExtension" in the SKS specification
    ///////////////////////////////////////////////////////////////////////////////////
    byte SUB_TYPE_EXTENSION                   = 0x00;
    byte SUB_TYPE_ENCRYPTED_EXTENSION         = 0x01;
    byte SUB_TYPE_PROPERTY_BAG                = 0x02;
    byte SUB_TYPE_LOGOTYPE                    = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // "ExportProtection" and "DeleteProtection" share constants (and code...)
    ///////////////////////////////////////////////////////////////////////////////////
    byte EXPORT_DELETE_PROTECTION_NONE        = 0x00;
    byte EXPORT_DELETE_PROTECTION_PIN         = 0x01;
    byte EXPORT_DELETE_PROTECTION_PUK         = 0x02;
    byte EXPORT_DELETE_PROTECTION_NOT_ALLOWED = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // "InputMethod" constants
    ///////////////////////////////////////////////////////////////////////////////////
    byte INPUT_METHOD_ANY                     = 0x00;
    byte INPUT_METHOD_PROGRAMMATIC            = 0x01;
    byte INPUT_METHOD_TRUSTED_GUI             = 0x02;

    ///////////////////////////////////////////////////////////////////////////////////
    // "BiometricProtection" constants
    ///////////////////////////////////////////////////////////////////////////////////
    byte BIOMETRIC_PROTECTION_NONE            = 0x00;
    byte BIOMETRIC_PROTECTION_ALTERNATIVE     = 0x01;
    byte BIOMETRIC_PROTECTION_COMBINED        = 0x02;
    byte BIOMETRIC_PROTECTION_EXCLUSIVE       = 0x03;

    ///////////////////////////////////////////////////////////////////////////////////
    // Default RSA support
    ///////////////////////////////////////////////////////////////////////////////////
    short[] SKS_DEFAULT_RSA_SUPPORT           = {1024, 2048};

    ///////////////////////////////////////////////////////////////////////////////////
    // Special algorithms
    ///////////////////////////////////////////////////////////////////////////////////
    String ALGORITHM_KEY_ATTEST_1             = "http://xmlns.webpki.org/sks/algorithm#key.1";
    String ALGORITHM_SESSION_ATTEST_1         = "http://xmlns.webpki.org/sks/algorithm#session.1";
    String ALGORITHM_ECDH_RAW                 = "http://xmlns.webpki.org/sks/algorithm#ecdh.raw";
    String ALGORITHM_NONE                     = "http://xmlns.webpki.org/sks/algorithm#none";

    ///////////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ///////////////////////////////////////////////////////////////////////////////////
    byte[] ZERO_LENGTH_ARRAY                  = new byte[0];
    short SKS_API_LEVEL                       = 99;
    int AES_CBC_PKCS5_PADDING                 = 32;

    ///////////////////////////////////////////////////////////////////////////////////
    // Core Provisioning API
    ///////////////////////////////////////////////////////////////////////////////////

    ProvisioningSession createProvisioningSession(String sessionKeyAlgorithm,
                                                  boolean privacyEnabled,
                                                  String serverSessionId,
                                                  ECPublicKey serverEphemeralKey,
                                                  String issuerUri,
                                                  PublicKey keyManagementKey, // Must be null if not applicable
                                                  int clientTime,
                                                  int sessionLifeTime,
                                                  short sessionKeyLimit) throws SKSException;

    byte[] closeProvisioningSession(int provisioningHandle,
                                    byte[] nonce,
                                    byte[] mac) throws SKSException;

    EnumeratedProvisioningSession enumerateProvisioningSessions(int provisioningHandle,
                                                                boolean provisioningState) throws SKSException;

    byte[] signProvisioningSessionData(int provisioningHandle,
                                       byte[] data) throws SKSException;

    KeyData createKeyEntry(int provisioningHandle,
                           String id,
                           String keyEntryAlgorithm,
                           byte[] serverSeed,  // May be null
                           boolean devicePinProtection,
                           int pinPolicyHandle,
                           byte[] pinValue,  // Must be null if not applicable
                           boolean enablePinCaching,
                           byte biometricProtection,
                           byte exportProtection,
                           byte deleteProtection,
                           byte appUsage,
                           String friendlyName,  // May be null
                           String keyAlgorithm,
                           byte[] keyParameters,  // Must be null if not applicable
                           String[] endorsedAlgorithms,
                           byte[] mac) throws SKSException;

    int getKeyHandle(int provisioningHandle,
                     String id) throws SKSException;

    void abortProvisioningSession(int provisioningHandle) throws SKSException;

    void setCertificatePath(int keyHandle,
                            X509Certificate[] certificatePath,
                            byte[] mac) throws SKSException;

    void addExtension(int keyHandle,
                      String type,
                      byte subType,
                      String qualifier,
                      byte[] extensionData,
                      byte[] mac) throws SKSException;

    void importSymmetricKey(int keyHandle,
                            byte[] encryptedKey,
                            byte[] mac) throws SKSException;

    void importPrivateKey(int keyHandle,
                          byte[] encryptedKey,
                          byte[] mac) throws SKSException;

    int createPinPolicy(int provisioningHandle,
                        String id,
                        int pukPolicyHandle,
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

    int createPukPolicy(int provisioningHandle,
                        String id,
                        byte[] pukValue,
                        byte format,
                        short retryLimit,
                        byte[] mac) throws SKSException;

    void updateKeyManagementKey(int provisioningHandle,
                                PublicKey keyManagementKey,
                                byte[] authorization) throws SKSException;

    ///////////////////////////////////////////////////////////////////////////////////
    // Post Provisioning (Management)
    ///////////////////////////////////////////////////////////////////////////////////

    void postDeleteKey(int provisioningHandle,
                       int targetKeyHandle,
                       byte[] authorization,
                       byte[] mac) throws SKSException;

    void postUnlockKey(int provisioningHandle,
                       int targetKeyHandle,
                       byte[] authorization,
                       byte[] mac) throws SKSException;

    void postUpdateKey(int keyHandle,
                       int targetKeyHandle,
                       byte[] authorization,
                       byte[] mac) throws SKSException;

    void postCloneKeyProtection(int keyHandle,
                                int targetKeyHandle,
                                byte[] authorization,
                                byte[] mac) throws SKSException;

    ///////////////////////////////////////////////////////////////////////////////////
    // "User" API
    ///////////////////////////////////////////////////////////////////////////////////

    KeyAttributes getKeyAttributes(int keyHandle) throws SKSException;

    EnumeratedKey enumerateKeys(int keyHandle) throws SKSException;

    byte[] signHashedData(int keyHandle,
                          String algorithm,
                          byte[] parameters,    // Must be null if not applicable
                          byte[] authorization, // Must be null if not applicable
                          byte[] data) throws SKSException;

    byte[] performHmac(int keyHandle,
                       String algorithm,
                       byte[] parameters,    // Must be null if not applicable
                       byte[] authorization, // Must be null if not applicable
                       byte[] data) throws SKSException;

    byte[] symmetricKeyEncrypt(int keyHandle,
                               String algorithm,
                               boolean mode,
                               byte[] parameters,    // Must be null if not applicable
                               byte[] authorization, // Must be null if not applicable
                               byte[] data) throws SKSException;

    byte[] asymmetricKeyDecrypt(int keyHandle,
                                String algorithm,
                                byte[] parameters,    // Must be null if not applicable
                                byte[] authorization, // Must be null if not applicable
                                byte[] data) throws SKSException;

    byte[] keyAgreement(int keyHandle,
                        String algorithm,
                        byte[] parameters,    // Must be null if not applicable
                        byte[] authorization, // Must be null if not applicable
                        ECPublicKey publicKey) throws SKSException;

    void deleteKey(int keyHandle,
                   byte[] authorization /* Must be null if not applicable */) throws SKSException;


    ///////////////////////////////////////////////////////////////////////////////////
    // Miscellaneous
    ///////////////////////////////////////////////////////////////////////////////////

    DeviceInfo getDeviceInfo() throws SKSException;

    Extension getExtension(int keyHandle,
                           String type) throws SKSException;

    KeyProtectionInfo getKeyProtectionInfo(int keyHandle) throws SKSException;

    void setProperty(int keyHandle,
                     String type,
                     String name,
                     String value) throws SKSException;

    void unlockKey(int keyHandle,
                   byte[] authorization) throws SKSException;

    void changePin(int keyHandle,
                   byte[] authorization,
                   byte[] newPin) throws SKSException;

    void setPin(int keyHandle,
                byte[] authorization,
                byte[] newPin) throws SKSException;

    byte[] exportKey(int keyHandle,
                     byte[] authorization /* Must be null if not applicable */) throws SKSException;

    String updateFirmware(byte[] chunk) throws SKSException;
}
