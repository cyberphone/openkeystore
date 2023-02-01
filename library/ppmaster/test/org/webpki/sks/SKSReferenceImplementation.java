/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
//#if ANDROID
package org.webpki.mobile.android.sks;

import android.os.Build;

import android.util.Log;
//#else
package org.webpki.sks;
//#endif

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
//#if !ANDROID
import java.security.KeyStore;
//#endif
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
//#if !BOUNCYCASTLE
//#if !ANDROID
import java.security.spec.NamedParameterSpec;
//#endif
//#endif
//#if ANDROID
import java.security.spec.X509EncodedKeySpec;
//#endif

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

//#if ANDROID
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
//#endif

//#if ANDROID
/*
 *                          ###########################
 *                          #  SKS - Secure Key Store #
 *                          ###########################
 *
 *  SKS is a cryptographic module that supports On-line Provisioning and Management
 *  of PKI, Symmetric keys, PINs, PUKs and Extension data.
 *
 *  This is an Android version of SKS.
 *
 *  Author: Anders Rundgren
 */
public class AndroidSKSImplementation implements SecureKeyStore, Serializable, GrantInterface {
//#else
/*
 *                          ###########################
 *                          #  SKS - Secure Key Store #
 *                          ###########################
 *
 *  SKS is a cryptographic module that supports On-line Provisioning and Management
 *  of PKI, Symmetric keys, PINs, PUKs and Extension data.
 *  
 *  VSDs (Virtual Security Domains), E2ES (End To End Security), and Transaction
 *  Oriented Provisioning enable multiple credential providers to securely and
 *  reliable share a key container, something which will become a necessity in
 *  mobile phones with embedded security hardware.
 *
 *  The following SKS Reference Implementation is intended to complement the
 *  specification by showing how the different constructs can be implemented.
 *
 *  In addition to the Reference Implementation there is a set of SKS JUnit tests
 *  that should work identical when performed on a "real" SKS token.
 *
 *  Compared to the SKS specification, the Reference Implementation uses a slightly
 *  more java-centric way of passing parameters, including "null" arguments, but the
 *  content is supposed to be identical.
 *  
 *  Note that persistence is not supported by the Reference Implementation.
 *
 *  Author: Anders Rundgren
 */
public class SKSReferenceImplementation implements SecureKeyStore, Serializable {
//#endif
    private static final long serialVersionUID = 15L;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS version and configuration data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final String SKS_VENDOR_NAME                    = "WebPKI.org";
//#if ANDROID
    static final String SKS_VENDOR_DESCRIPTION             = "SKS for Android";
    static final String SKS_UPDATE_URL                     = null;  // Change here to test or disable
    static final boolean SKS_DEVICE_PIN_SUPPORT            = false; // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT             = true;  // Change here to test or disable

    ///////////////////////////////////////////////////////////////////////////////////
    // Default RSA support
    ///////////////////////////////////////////////////////////////////////////////////
    static final boolean SKS_RSA_EXPONENT_SUPPORT          = false;
    static final short[] SKS_DEFAULT_RSA_SUPPORT           = {2048};

//#else
    static final String SKS_VENDOR_DESCRIPTION             = "SKS Reference - Java Emulator Edition";
    static final String SKS_UPDATE_URL                     = null;  // Change here to test or disable
    static final boolean SKS_DEVICE_PIN_SUPPORT            = true;  // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT             = true;  // Change here to test or disable

    ///////////////////////////////////////////////////////////////////////////////////
    // Default RSA support
    ///////////////////////////////////////////////////////////////////////////////////
    static final boolean SKS_RSA_EXPONENT_SUPPORT          = true;  // Change here to test or disable
    static final short[] SKS_DEFAULT_RSA_SUPPORT           = {1024, 2048};

//#endif
    static final int MAX_LENGTH_CRYPTO_DATA                = 16384;
    static final int MAX_LENGTH_EXTENSION_DATA             = 250000; // A reasonably big image

    static final char[] BASE64_URL = {'A','B','C','D','E','F','G','H',
                                      'I','J','K','L','M','N','O','P',
                                      'Q','R','S','T','U','V','W','X',
                                      'Y','Z','a','b','c','d','e','f',
                                      'g','h','i','j','k','l','m','n',
                                      'o','p','q','r','s','t','u','v',
                                      'w','x','y','z','0','1','2','3',
                                      '4','5','6','7','8','9','-','_'};

    int nextKeyHandle = 1;
    LinkedHashMap<Integer, KeyEntry> keys = new LinkedHashMap<>();

    int nextProvHandle = 1;
    LinkedHashMap<Integer, Provisioning> provisionings = new LinkedHashMap<>();

    int nextPinHandle = 1;
    LinkedHashMap<Integer, PINPolicy> pinPolicies = new LinkedHashMap<>();

    int nextPukHandle = 1;
    LinkedHashMap<Integer, PUKPolicy> pukPolicies = new LinkedHashMap<>();

    X509Certificate[] deviceCertificatePath;
//#if ANDROID
    private transient PrivateKey attestationKey;                  // Hardware backed do not serialize

    private static final String SKS_DEBUG = "SKS";                // Android SKS debug constant

    AndroidSKSImplementation() {
    }

    void setDeviceCredentials(X509Certificate[] deviceCertificatePath, PrivateKey attestationKey) {
        this.deviceCertificatePath = deviceCertificatePath;
        this.attestationKey = attestationKey;
    }

    void logCertificateOperation(KeyEntry keyEntry, String operation) {
        Log.i(SKS_DEBUG, certificateLogData(keyEntry) + " " + operation);
    }

    String certificateLogData(KeyEntry keyEntry) {
        return "Certificate for '" + keyEntry.certificatePath[0].getSubjectX500Principal().getName() +
               "' Serial=" + keyEntry.certificatePath[0].getSerialNumber();
    }
//#else
    private PrivateKey attestationKey;

    static final char[] ATTESTATION_KEY_PASSWORD = {'t', 'e', 's', 't', 'i', 'n', 'g'};

    static final String ATTESTATION_KEY_ALIAS = "mykey";

    public SKSReferenceImplementation() throws IOException, GeneralSecurityException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(getClass().getResourceAsStream("attestationkeystore.jks"), ATTESTATION_KEY_PASSWORD);
        attestationKey = (PrivateKey)ks.getKey(ATTESTATION_KEY_ALIAS, ATTESTATION_KEY_PASSWORD);
        deviceCertificatePath = new X509Certificate[]{(X509Certificate) ks.getCertificate(ATTESTATION_KEY_ALIAS)};
    }
//#endif

    abstract class NameSpace implements Serializable {
        private static final long serialVersionUID = 1L;

        String id;

        Provisioning owner;

        NameSpace(Provisioning owner, String id) {
            //////////////////////////////////////////////////////////////////////
            // Keys, PINs and PUKs share virtual ID space during provisioning
            //////////////////////////////////////////////////////////////////////
            if (owner.names.get(id) != null) {
                abort("Duplicate \"" + VAR_ID + "\" : " + id);
            }
            checkIdSyntax(id, VAR_ID);
            owner.names.put(id, false);
            this.owner = owner;
            this.id = id;
        }
    }


    static void checkIdSyntax(String identifier, String symbolicName) {
        boolean flag = false;
        if (identifier.length() == 0 || identifier.length() > MAX_LENGTH_ID_TYPE) {
            flag = true;
        } else for (char c : identifier.toCharArray()) {
            /////////////////////////////////////////////////
            // The restricted ID
            /////////////////////////////////////////////////
            if (c < '!' || c > '~') {
                flag = true;
                break;
            }
        }
        if (flag) {
            abort("Malformed \"" + symbolicName + "\" : " + identifier);
        }
    }


    class KeyEntry extends NameSpace implements Serializable {
        private static final long serialVersionUID = 1L;

        int keyHandle;
//#if ANDROID

// SKS update of keys mandate that keyHandles stay intact.
// To cope with this requirement updated keys must be remapped...
        Integer remappedKeyHandle;
//#endif

        byte appUsage;

        PublicKey publicKey;     // In this implementation overwritten by "setCertificatePath"
//#if ANDROID
        PrivateKey exportablePrivateKey;  // Not stored in AndroidKeyStore
//#else
        PrivateKey privateKey;   // Overwritten if "importPrivateKey" is called
//#endif
        X509Certificate[] certificatePath;

        byte[] symmetricKey;     // Defined by "importSymmetricKey"
//#if ANDROID

        LinkedHashSet<String> grantedDomains = new LinkedHashSet<>();
//#endif

        LinkedHashSet<String> endorsedAlgorithms;

        String friendlyName;

        boolean devicePinProtection;

        byte[] pinValue;
        short errorCount;
        PINPolicy pinPolicy;
        boolean enablePinCaching;

        byte biometricProtection;
        byte exportProtection;
        byte deleteProtection;

        byte keyBackup;


        LinkedHashMap<String, ExtObject> extensions = new LinkedHashMap<>();

        KeyEntry(Provisioning owner, String id) {
            super(owner, id);
            keyHandle = nextKeyHandle++;
            keys.put(keyHandle, this);
        }

        void authError() {
            abort("\"" + VAR_AUTHORIZATION + "\" error for key #" + keyHandle, SKSException.ERROR_AUTHORIZATION);
        }

//#if ANDROID
        PrivateKey getPrivateKey() throws GeneralSecurityException {
            return exportablePrivateKey == null ?
              HardwareKeyStore.getPrivateKey(getKeyId()) : exportablePrivateKey;
        }
        
        String getKeyId() {
            return String.valueOf(remappedKeyHandle == null ? keyHandle : (int)remappedKeyHandle);
        }

//#endif
        @SuppressWarnings("fallthrough")
        ArrayList<KeyEntry> getPinSynchronizedKeys() {
            ArrayList<KeyEntry> group = new ArrayList<>();
            if (pinPolicy.grouping == PIN_GROUPING_NONE) {
                group.add(this);
            } else {
                /////////////////////////////////////////////////////////////////////////////////////////
                // Multiple keys "sharing" a PIN means that status and values must be distributed
                /////////////////////////////////////////////////////////////////////////////////////////
                for (KeyEntry keyEntry : keys.values()) {
                    if (keyEntry.pinPolicy == pinPolicy) {
                        switch (pinPolicy.grouping) {
                            case PIN_GROUPING_UNIQUE:
                                if (appUsage != keyEntry.appUsage) {
                                    continue;
                                }
                            case PIN_GROUPING_SIGN_PLUS_STD:
                                if ((appUsage == APP_USAGE_SIGNATURE) ^ (keyEntry.appUsage == APP_USAGE_SIGNATURE)) {
                                    continue;
                                }
                        }
                        group.add(keyEntry);
                    }
                }
            }
            return group;
        }

        void setErrorCounter(short newErrorCount) {
            for (KeyEntry keyEntry : getPinSynchronizedKeys()) {
                keyEntry.errorCount = newErrorCount;
            }
        }

        void updatePin(byte[] newPin) {
            for (KeyEntry keyEntry : getPinSynchronizedKeys()) {
                keyEntry.pinValue = newPin;
            }
        }

        void verifyPin(byte[] pin) {
            ///////////////////////////////////////////////////////////////////////////////////
            // If there is no PIN policy there is nothing to verify...
            ///////////////////////////////////////////////////////////////////////////////////
            if (pinPolicy == null) {
                if (devicePinProtection) {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Only for testing purposes.  Device PINs are out-of-scope for the SKS API
                    ///////////////////////////////////////////////////////////////////////////////////
                    if (!Arrays.equals(pin, new byte[]{'1', '2', '3', '4'})) {
                        authError();
                    }
                } else if (pin != null) {
                    abort("Redundant authorization information for key #" + keyHandle);
                }
            } else {
                ///////////////////////////////////////////////////////////////////////////////////
                // Check that we haven't already passed the limit
                ///////////////////////////////////////////////////////////////////////////////////
                if (errorCount >= pinPolicy.retryLimit) {
                    authError();
                }

                ///////////////////////////////////////////////////////////////////////////////////
                // Check the PIN value
                ///////////////////////////////////////////////////////////////////////////////////
                if (!Arrays.equals(this.pinValue, pin)) {
                    setErrorCounter(++errorCount);
                    authError();
                }

                ///////////////////////////////////////////////////////////////////////////////////
                // A success always resets the PIN error counter(s)
                ///////////////////////////////////////////////////////////////////////////////////
                setErrorCounter((short) 0);
            }
        }
        
        void authorize(boolean biometricAuth, byte[] pin) {
            if (biometricAuth) {
                if (biometricProtection == BIOMETRIC_PROTECTION_NONE) {
                    abort("Biometric option invalid for key #" + keyHandle);
                }
                if (biometricProtection == BIOMETRIC_PROTECTION_EXCLUSIVE || 
                    biometricProtection == BIOMETRIC_PROTECTION_ALTERNATIVE) {
                    if (pin != null) {
                        abort("Biometric + pin option invalid for key #" + keyHandle);
                    }
                } else {
                    verifyPin(pin);
                }
            } else {
                if (biometricProtection == BIOMETRIC_PROTECTION_COMBINED ||
                    biometricProtection == BIOMETRIC_PROTECTION_EXCLUSIVE) {
                    abort("Missing biometric for key #" + keyHandle);
                }
                verifyPin(pin);
            }
        }

        void verifyPuk(byte[] puk) {
            ///////////////////////////////////////////////////////////////////////////////////
            // Check that this key really has a PUK...
            ///////////////////////////////////////////////////////////////////////////////////
            if (pinPolicy == null || pinPolicy.pukPolicy == null) {
                abort("Key #" + keyHandle + " has no PUK");
            }

            PUKPolicy pukPolicy = pinPolicy.pukPolicy;
            if (pukPolicy.retryLimit > 0) {
                ///////////////////////////////////////////////////////////////////////////////////
                // The key is using the "standard" retry PUK policy
                ///////////////////////////////////////////////////////////////////////////////////
                if (pukPolicy.errorCount >= pukPolicy.retryLimit) {
                    authError();
                }
            } else {
                ///////////////////////////////////////////////////////////////////////////////////
                // The "liberal" PUK policy never locks up but introduces a mandatory delay...
                ///////////////////////////////////////////////////////////////////////////////////
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check the PUK value
            ///////////////////////////////////////////////////////////////////////////////////
            if (!Arrays.equals(pukPolicy.pukValue, puk)) {
                if (pukPolicy.retryLimit > 0) {
                    ++pukPolicy.errorCount;
                }
                authError();
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // A success always resets the PUK error counter
            ///////////////////////////////////////////////////////////////////////////////////
            pukPolicy.errorCount = 0;
        }

        void authorizeExportOrDeleteOperation(byte policy, byte[] authorization) {
            switch (policy) {
                case EXPORT_DELETE_PROTECTION_PIN:
                    verifyPin(authorization);
                    return;

                case EXPORT_DELETE_PROTECTION_PUK:
                    verifyPuk(authorization);
                    return;

                case EXPORT_DELETE_PROTECTION_NOT_ALLOWED:
                    abort("Operation not allowed on key #" + keyHandle, SKSException.ERROR_NOT_ALLOWED);
            }
            if (authorization != null) {
                abort("Redundant authorization information for key #" + keyHandle);
            }
        }

        void checkEECertificateAvailability() {
            if (certificatePath == null) {
                abort("Missing \"setCertificatePath\" for: " + id);
            }
        }

        MacBuilder getEeCertMacBuilder(byte[] method) throws IOException, GeneralSecurityException {
            checkEECertificateAvailability();
            MacBuilder macBuilder = owner.getMacBuilderForMethodCall(method);
            macBuilder.addArray(certificatePath[0].getEncoded());
            return macBuilder;
        }

        void validateTargetKeyReference(MacBuilder verifier,
                                        byte[] mac,
                                        byte[] authorization,
                                        Provisioning provisioning) throws IOException, GeneralSecurityException {
            ///////////////////////////////////////////////////////////////////////////////////
            // "Sanity check"
            ///////////////////////////////////////////////////////////////////////////////////
            if (provisioning.privacyEnabled ^ owner.privacyEnabled) {
                abort("Inconsistent use of the \"" + VAR_PRIVACY_ENABLED + "\" attribute for key #" + keyHandle);
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify MAC
            ///////////////////////////////////////////////////////////////////////////////////
            verifier.addArray(authorization);
            provisioning.verifyMac(verifier, mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify KMK signature
            ///////////////////////////////////////////////////////////////////////////////////
            if (!owner.verifyKeyManagementKeyAuthorization(KMK_TARGET_KEY_REFERENCE,
                    provisioning.getMacBuilder(getDeviceID(provisioning.privacyEnabled))
                        .addVerbatim(certificatePath[0].getEncoded()).getResult(), authorization)) {
                abort("\"" + VAR_AUTHORIZATION + "\" signature did not verify for key #" + keyHandle);
            }
        }

        boolean isSymmetric() {
            return symmetricKey != null;
        }
        
        boolean isRsa() {
            return publicKey instanceof RSAKey;
        }
        
        boolean isEc() {
            return publicKey instanceof ECKey;
        }

        void checkCryptoDataSize(byte[] data) {
            if (data.length > MAX_LENGTH_CRYPTO_DATA) {
                abort("Exceeded \"" + VAR_CRYPTO_DATA_SIZE + "\" for key #" + keyHandle);
            }
        }

        void setAndVerifyServerBackupFlag() {
            if ((keyBackup & KeyProtectionInfo.KEYBACKUP_IMPORTED) != 0) {
                abort("Mutiple key imports for: " + id);
            }
            keyBackup |= KeyProtectionInfo.KEYBACKUP_IMPORTED;
        }
    }


    class ExtObject implements Serializable {
        private static final long serialVersionUID = 1L;

        String qualifier;
        byte[] extensionData;
        byte subType;
    }


    class PINPolicy extends NameSpace implements Serializable {
        private static final long serialVersionUID = 1L;

        int pinPolicyHandle;

        PUKPolicy pukPolicy;

        short retryLimit;
        byte format;
        boolean userDefined;
        boolean userModifiable;
        byte inputMethod;
        byte grouping;
        byte patternRestrictions;
        short minLength;
        short maxLength;

        PINPolicy(Provisioning owner, String id) {
            super(owner, id);
            pinPolicyHandle = nextPinHandle++;
            pinPolicies.put(pinPolicyHandle, this);
        }
    }


    class PUKPolicy extends NameSpace implements Serializable {
        private static final long serialVersionUID = 1L;

        int pukPolicyHandle;

        byte[] pukValue;
        byte format;
        short retryLimit;
        short errorCount;

        PUKPolicy(Provisioning owner, String id) {
            super(owner, id);
            pukPolicyHandle = nextPukHandle++;
            pukPolicies.put(pukPolicyHandle, this);
        }
    }


    class Provisioning implements Serializable {
        private static final long serialVersionUID = 1L;

        int provisioningHandle;

        // The virtual/shared name-space
        LinkedHashMap<String, Boolean> names = new LinkedHashMap<>();

        // Post provisioning management
        ArrayList<PostProvisioningObject> postProvisioningObjects = new ArrayList<>();

        boolean privacyEnabled;
        String clientSessionId;
        String serverSessionId;
        String issuerUri;
        byte[] sessionKey;
        boolean open = true;
        PublicKey keyManagementKey;
        short macSequenceCounter;
        int clientTime;
        short sessionLifeTime;
        short sessionKeyLimit;

        Provisioning() {
            provisioningHandle = nextProvHandle++;
            provisionings.put(provisioningHandle, this);
        }

        void verifyMac(MacBuilder actualMac, byte[] claimedMac) throws IOException {
            if (!Arrays.equals(actualMac.getResult(), claimedMac)) {
                abort("MAC error", SKSException.ERROR_MAC);
            }
        }

        byte[] decrypt(byte[] data) throws IOException, GeneralSecurityException {
            byte[] key = getMacBuilder(ZERO_LENGTH_ARRAY).addVerbatim(KDF_ENCRYPTION_KEY).getResult();
            Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            crypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(data, 0, 16));
            return crypt.doFinal(data, 16, data.length - 16);
        }

        MacBuilder getMacBuilder(byte[] keyModifier) throws GeneralSecurityException {
            if (sessionKeyLimit-- <= 0) {
                abort("\"" + VAR_SESSION_KEY_LIMIT + "\" exceeded");
            }
            return new MacBuilder(addArrays(sessionKey, keyModifier));
        }

        MacBuilder getMacBuilderForMethodCall(byte[] method) throws GeneralSecurityException {
            short q = macSequenceCounter++;
            return getMacBuilder(addArrays(method, new byte[]{(byte) (q >>> 8), (byte) q}));
        }

        KeyEntry getTargetKey(int keyHandle) {
            KeyEntry keyEntry = keys.get(keyHandle);
            if (keyEntry == null) {
                abort("Key not found #" + keyHandle, SKSException.ERROR_NO_KEY);
            }
            if (keyEntry.owner.open) {
                abort("Key #" + keyHandle + " still in provisioning");
            }
            if (keyEntry.owner.keyManagementKey == null) {
                abort("Key #" + keyHandle + " belongs to a non-updatable provisioning session");
            }
            return keyEntry;
        }

        void addPostProvisioningObject(KeyEntry targetKeyEntry, 
                                       KeyEntry newKey,
                                       boolean updateOrDelete) {
            for (PostProvisioningObject postOp : postProvisioningObjects) {
                if (postOp.newKey != null && postOp.newKey == newKey) {
                    abort("New key used for multiple operations: " + newKey.id);
                }
                if (postOp.targetKeyEntry == targetKeyEntry) {
                    ////////////////////////////////////////////////////////////////////////////////////////////////
                    // Multiple targeting of the same old key is OK but has restrictions
                    ////////////////////////////////////////////////////////////////////////////////////////////////
                    if ((newKey == null && updateOrDelete) || 
                        (postOp.newKey == null && postOp.updateOrDelete)) // postDeleteKey
                    {
                        abort("Delete wasn't exclusive for key #" + targetKeyEntry.keyHandle);
                    } else if (newKey == null && postOp.newKey == null) // postUnlockKey * 2
                    {
                        abort("Multiple unlocks of key #" + targetKeyEntry.keyHandle);
                    } else if (updateOrDelete && postOp.updateOrDelete) {
                        abort("Multiple updates of key #" + targetKeyEntry.keyHandle);
                    }
                }
            }
            postProvisioningObjects.add(new PostProvisioningObject(targetKeyEntry, newKey, updateOrDelete));
        }

        void rangeTest(byte value, byte lowLimit, byte highLimit, String objectName) {
            if (value > highLimit || value < lowLimit) {
                abort("Invalid \"" + objectName + "\" value=" + value);
            }
        }

        void passphraseFormatTest(byte format) {
            rangeTest(format, PASSPHRASE_FORMAT_NUMERIC, PASSPHRASE_FORMAT_BINARY, "Format");
        }

        void retryLimitTest(short retryLimit, short min) {
            if (retryLimit < min || retryLimit > MAX_RETRY_LIMIT) {
                abort("Invalid \"" + VAR_RETRY_LIMIT + "\" value=" + retryLimit);
            }
        }

        boolean verifyKeyManagementKeyAuthorization(byte[] kmkKdf,
                                                    byte[] argument,
                                                    byte[] authorization) throws GeneralSecurityException {
            return new SignatureWrapper(keyManagementKey instanceof RSAKey ?
                                           "SHA256WithRSA" : "SHA256WithECDSA",
                                        keyManagementKey)
                .update(kmkKdf)
                .update(argument)
                .verify(authorization);
        }
    }


    class ByteWriter {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        void addByte(byte value) {
            baos.write(value);
        }

        void addArrayCore(byte[] value) throws IOException{
            baos.write(value);
        }

        void addBool(boolean value) {
            addByte((byte)(value ? 1 : 0));
        }

        void addShort(int value) {
            addByte((byte)(value >>> 8));
            addByte((byte)(value));
        }

        void addArray(byte[] value) throws IOException {
            addShort(value.length);
            baos.write(value);
        }

        void addString(String string) throws IOException {
            addArray(getBinary(string));
        }
        
        void addInt(int value) {
            addByte((byte)(value >>> 24));
            addByte((byte)(value >>> 16));
            addByte((byte)(value >>> 8));
            addByte((byte)(value));
        }
        
        void addBlob(byte[] blob) throws IOException {
            addInt(blob.length);
            addArrayCore(blob);
        }
        
        byte[] getData() throws IOException {
             return baos.toByteArray();
        }
        
        byte[] getResult() throws IOException, GeneralSecurityException {
            return null;
        }
    }
    

    class MacBuilder extends ByteWriter implements Serializable {
        private static final long serialVersionUID = 1L;

        Mac mac;

        MacBuilder(byte[] key) throws GeneralSecurityException {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "RAW"));
        }

        MacBuilder addVerbatim(byte[] data) throws IOException {
            addArrayCore(data);
            return this;
        }

        @Override
        byte[] getResult() throws IOException {
            mac.update(getData());
            return mac.doFinal();
        }
    }


    class AttestationSignatureGenerator extends ByteWriter {

        SignatureWrapper signer;

        AttestationSignatureGenerator() throws GeneralSecurityException {
            signer = new SignatureWrapper(attestationKey instanceof RSAKey ?
                                                                  "SHA256withRSA" : "SHA256withECDSA",
                                          attestationKey);
        }

        @Override
        byte[] getResult() throws IOException, GeneralSecurityException {
            return signer.update(getData()).sign();
        }
    }


    class PostProvisioningObject implements Serializable {
        private static final long serialVersionUID = 1L;

        KeyEntry targetKeyEntry;
        KeyEntry newKey;           // null for postDeleteKey and postUnlockKey
        boolean updateOrDelete;    // true for postUpdateKey and postDeleteKey

        PostProvisioningObject(KeyEntry targetKeyEntry, KeyEntry newKey, boolean updateOrDelete) {
            this.targetKeyEntry = targetKeyEntry;
            this.newKey = newKey;
            this.updateOrDelete = updateOrDelete;
        }
    }


    class SignatureWrapper {
        static final int ASN1_SEQUENCE = 0x30;
        static final int ASN1_INTEGER = 0x02;

        static final int LEADING_ZERO = 0x00;

        Signature instance;
        boolean modifySignature;
        int extendTo;

        public SignatureWrapper(String algorithm, PublicKey publicKey) throws GeneralSecurityException {
            instance = Signature.getInstance(algorithm);
            instance.initVerify(publicKey);
            modifySignature = publicKey instanceof ECKey;
            if (modifySignature) {
                extendTo = getEcPointLength((ECKey) publicKey);
            }
        }

        public SignatureWrapper(String algorithm, PrivateKey privateKey) throws GeneralSecurityException {
            instance = Signature.getInstance(algorithm);
            instance.initSign(privateKey);
            modifySignature = privateKey instanceof ECKey;
            if (modifySignature) {
                extendTo = getEcPointLength((ECKey) privateKey);
            }
        }

        public SignatureWrapper update(byte[] data) throws GeneralSecurityException {
            instance.update(data);
            return this;
        }

        public SignatureWrapper update(byte data) throws GeneralSecurityException {
            instance.update(data);
            return this;
        }

        public boolean verify(byte[] signature) throws GeneralSecurityException {
            if (!modifySignature) {
                return instance.verify(signature);
            }
            if (extendTo != signature.length / 2) {
                throw new GeneralSecurityException("Signature length error");
            }

            int i = extendTo;
            while (i > 0 && signature[extendTo - i] == LEADING_ZERO) {
                i--;
            }
            int j = i;
            if (signature[extendTo - i] < 0) {
                j++;
            }

            int k = extendTo;
            while (k > 0 && signature[2 * extendTo - k] == LEADING_ZERO) {
                k--;
            }
            int l = k;
            if (signature[2 * extendTo - k] < 0) {
                l++;
            }

            int len = 2 + j + 2 + l;
            int offset = 1;
            byte derCodedSignature[];
            if (len < 128) {
                derCodedSignature = new byte[len + 2];
            } else {
                derCodedSignature = new byte[len + 3];
                derCodedSignature[1] = (byte) 0x81;
                offset = 2;
            }
            derCodedSignature[0] = ASN1_SEQUENCE;
            derCodedSignature[offset++] = (byte) len;
            derCodedSignature[offset++] = ASN1_INTEGER;
            derCodedSignature[offset++] = (byte) j;
            System.arraycopy(signature, extendTo - i, derCodedSignature, offset + j - i, i);
            offset += j;
            derCodedSignature[offset++] = ASN1_INTEGER;
            derCodedSignature[offset++] = (byte) l;
            System.arraycopy(signature, 2 * extendTo - k, derCodedSignature, offset + l - k, k);
            return instance.verify(derCodedSignature);
        }

        byte[] sign() throws GeneralSecurityException {
            byte[] signature = instance.sign();
            if (!modifySignature) {
                return signature;
            }
            int index = 2;
            byte[] integerPairs = new byte[extendTo << 1];
            if (signature[0] != ASN1_SEQUENCE) {
                throw new GeneralSecurityException("Not SEQUENCE");
            }
            int length = signature[1];
            if (length < 4) {
                if (length != -127) {
                    throw new GeneralSecurityException("Bad ASN.1 length");
                }
                length = signature[index++] & 0xFF;
            }
            for (int offset = 0; offset <= extendTo; offset += extendTo) {
                if (signature[index++] != ASN1_INTEGER) {
                    throw new GeneralSecurityException("Not INTEGER");
                }
                int l = signature[index++];
                while (l > extendTo) {
                    if (signature[index++] != LEADING_ZERO) {
                        throw new GeneralSecurityException("Bad INTEGER");
                    }
                    l--;
                }
                System.arraycopy(signature, index, integerPairs, offset + extendTo - l, l);
                index += l;
            }
            if (index != signature.length) {
                throw new GeneralSecurityException("ASN.1 Length error");
            }
            return integerPairs;
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Algorithm Support
    /////////////////////////////////////////////////////////////////////////////////////////////

    static class Algorithm implements Serializable {
        private static final long serialVersionUID = 1L;

        int mask;
        String jceName;
        ECParameterSpec ecParameterSpec;
        int ecPointLength;

        void addEcCurve(int ecPointLength) {
            this.ecPointLength = ecPointLength;
            try {
                AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
                parameters.init(new ECGenParameterSpec(jceName));
                ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
            } catch (Exception e) {
 //#if ANDROID
                try {
                    // Android 7 fix...
                    Log.i("OL1", jceName);
                    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
                    keyGen.initialize(new ECGenParameterSpec(jceName));
                    ecParameterSpec = ((ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
                        new X509EncodedKeySpec(
                                keyGen.generateKeyPair().getPublic().getEncoded()))).getParams();
                } catch (Exception e1) {
                    Log.e("OL2", jceName, e);
                }
//#endif
                new RuntimeException(e);
            }

        }
    }

    static LinkedHashMap<String, Algorithm> supportedAlgorithms = new LinkedHashMap<>();

    static Algorithm addAlgorithm(String uri, String jceName, int mask) {
        Algorithm alg = new Algorithm();
        alg.mask = mask;
        alg.jceName = jceName;
        supportedAlgorithms.put(uri, alg);
        return alg;
    }

    static final int ALG_SYM_ENC   = 0x00000001;
    static final int ALG_IV_REQ    = 0x00000002;
    static final int ALG_IV_INT    = 0x00000004;
    static final int ALG_SYML_128  = 0x00000008;
    static final int ALG_SYML_192  = 0x00000010;
    static final int ALG_SYML_256  = 0x00000020;
    static final int ALG_HMAC      = 0x00000040;
    static final int ALG_ASYM_ENC  = 0x00000080;
    static final int ALG_ASYM_SGN  = 0x00000100;
    static final int ALG_RSA_KEY   = 0x00004000;
    static final int ALG_RSA_GMSK  = 0x00003FFF;
    static final int ALG_RSA_EXP   = 0x00008000;
    static final int ALG_EDDSA_KEY = 0x00010000;
    static final int ALG_MFG1_256  = 0x00200000;
    static final int ALG_NONE      = 0x00800000;
    static final int ALG_ASYM_KA   = 0x01000000;
    static final int ALG_AES_PAD   = 0x02000000;
    static final int ALG_EC_KEY    = 0x04000000;
    static final int ALG_KEY_GEN   = 0x08000000;
    static final int ALG_KEY_PARM  = 0x10000000;
    static final int ALG_SYM_KEY   = 0x20000000;

    static {
        //////////////////////////////////////////////////////////////////////////////////////
        //  Symmetric Key Encryption and Decryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_KEY | ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_128);

        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_KEY | ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_192);

        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_KEY | ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_256);

        addAlgorithm("https://webpki.github.io/sks/algorithm#aes.ecb.nopad",
                     "AES/ECB/NoPadding",
                     ALG_SYM_KEY | ALG_SYM_ENC | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256 |
                     ALG_AES_PAD);

        addAlgorithm("https://webpki.github.io/sks/algorithm#aes.cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_KEY | ALG_SYM_ENC | ALG_IV_REQ | ALG_SYML_128 | ALG_SYML_192 | 
                     ALG_SYML_256);

        //////////////////////////////////////////////////////////////////////////////////////
        //  HMAC Operations
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1", 
                     "HmacSHA1", 
                     ALG_SYM_KEY | ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", 
                     "HmacSHA256", 
                     ALG_SYM_KEY | ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", 
                     "HmacSHA384", 
                     ALG_SYM_KEY | ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
                     "HmacSHA512", 
                     ALG_SYM_KEY | ALG_HMAC);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Decryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("https://webpki.github.io/sks/algorithm#rsa.es.pkcs1_5",
                     "RSA/ECB/PKCS1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("https://webpki.github.io/sks/algorithm#rsa.oaep.sha1",
                     "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("https://webpki.github.io/sks/algorithm#rsa.oaep.sha256",
                     "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY | ALG_MFG1_256);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Diffie-Hellman Key Agreement
        //////////////////////////////////////////////////////////////////////////////////////
//#if ANDROID

        // ECDH is not supported by AndroidKeyStore
/*
        addAlgorithm("https://webpki.github.io/sks/algorithm#ecdh.raw",
                     "ECDH",
                     ALG_ASYM_KA | ALG_EC_KEY);
*/
//#else
        addAlgorithm("https://webpki.github.io/sks/algorithm#ecdh.raw",
                     "ECDH",
                     ALG_ASYM_KA | ALG_EC_KEY);
//#endif        

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Signatures
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                     "SHA256withRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                     "SHA384withRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
                     "SHA512withRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                     "SHA256withECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
                     "SHA384withECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
                     "SHA512withECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Generation
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("https://webpki.github.io/sks/algorithm#ec.nist.p256",
                     "secp256r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve(32);

        addAlgorithm("https://webpki.github.io/sks/algorithm#ec.nist.p384",
                     "secp384r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve(48);

        addAlgorithm("https://webpki.github.io/sks/algorithm#ec.nist.p521",
                     "secp521r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve(66);

//#if BOUNCYCASTLE
        addAlgorithm("https://webpki.github.io/sks/algorithm#ec.brainpool.p256r1",
                     "brainpoolP256r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve(32);

//#endif
        for (short rsa_size : SKS_DEFAULT_RSA_SUPPORT) {
            addAlgorithm("https://webpki.github.io/sks/algorithm#rsa" + rsa_size,
                         null, ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            if (SKS_RSA_EXPONENT_SUPPORT) {
                addAlgorithm("https://webpki.github.io/sks/algorithm#rsa" + rsa_size + ".exp",
                             null, ALG_KEY_PARM | ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            }
        }
//#if !BOUNCYCASTLE
//#if ANDROID
        if (Build.VERSION.SDK_INT >= 33) {
//#endif
            addAlgorithm("https://webpki.github.io/sks/algorithm#ed25519",
                         "Ed25519",
                         ALG_ASYM_SGN | ALG_EDDSA_KEY | ALG_KEY_GEN).ecPointLength = 32;
//#if ANDROID
        }
//#endif
//#endif
        
        //////////////////////////////////////////////////////////////////////////////////////
        //  Special Algorithms
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm(ALGORITHM_SESSION_ATTEST_1, null, 0);

        addAlgorithm(ALGORITHM_KEY_ATTEST_1, null, 0);

        addAlgorithm("https://webpki.github.io/sks/algorithm#none", null, ALG_NONE);

    }

    static final byte[] RSA_ENCRYPTION_OID = {(byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86, 
                                              (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D,
                                              (byte) 0x01, (byte) 0x01, (byte) 0x01};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Utility Functions
    /////////////////////////////////////////////////////////////////////////////////////////////

    byte[] getDeviceID(boolean privacyEnabled) throws GeneralSecurityException {
        return privacyEnabled ? KDF_ANONYMOUS : deviceCertificatePath[0].getEncoded();
    }

    Provisioning getProvisioningSession(int provisioningHandle) {
        Provisioning provisioning = provisionings.get(provisioningHandle);
        if (provisioning == null) {
            abort("No such provisioning session: " + provisioningHandle, SKSException.ERROR_NO_SESSION);
        }
        return provisioning;
    }

    Provisioning getOpenProvisioningSession(int provisioningHandle) {
        Provisioning provisioning = getProvisioningSession(provisioningHandle);
        if (!provisioning.open) {
            abort("Session not open: " + provisioningHandle, SKSException.ERROR_NO_SESSION);
        }
        return provisioning;
    }

    Provisioning getClosedProvisioningSession(int provisioningHandle) {
        Provisioning provisioning = getProvisioningSession(provisioningHandle);
        if (provisioning.open) {
            abort("Session is open: " + provisioningHandle, SKSException.ERROR_NOT_ALLOWED);
        }
        return provisioning;
    }

    byte[] getBinary(String string) throws IOException {
        return string.getBytes("utf-8");
    }

    int getShort(byte[] buffer, int index) {
        return ((buffer[index++] << 8) & 0xFFFF) + (buffer[index] & 0xFF);
    }

    KeyEntry getOpenKey(int keyHandle) {
        KeyEntry keyEntry = keys.get(keyHandle);
        if (keyEntry == null) {
            abort("Key not found #" + keyHandle, SKSException.ERROR_NO_KEY);
        }
        if (!keyEntry.owner.open) {
            abort("Key #" + keyHandle + " not belonging to open session", SKSException.ERROR_NO_KEY);
        }
        return keyEntry;
    }

    KeyEntry getStdKey(int keyHandle) {
        KeyEntry keyEntry = keys.get(keyHandle);
        if (keyEntry == null) {
            abort("Key not found #" + keyHandle, SKSException.ERROR_NO_KEY);
        }
        if (keyEntry.owner.open) {
            abort("Key #" + keyHandle + " still in provisioning", SKSException.ERROR_NO_KEY);
        }
        return keyEntry;
    }

    EnumeratedKey getKey(Iterator<KeyEntry> iter) {
        while (iter.hasNext()) {
            KeyEntry keyEntry = iter.next();
            if (!keyEntry.owner.open) {
                return new EnumeratedKey(keyEntry.keyHandle, keyEntry.owner.provisioningHandle);
            }
        }
        return null;
    }

    void deleteObject(LinkedHashMap<Integer, ?> objects, Provisioning provisioning) {
        Iterator<?> list = objects.values().iterator();
        while (list.hasNext()) {
            NameSpace element = (NameSpace) list.next();
            if (element.owner == provisioning) {
                list.remove();
            }
        }
    }

    EnumeratedProvisioningSession getProvisioning(Iterator<Provisioning> iter, boolean provisioningState) {
        while (iter.hasNext()) {
            Provisioning provisioning = iter.next();
            if (provisioning.open == provisioningState) {
                return new EnumeratedProvisioningSession(provisioning.provisioningHandle,
                                                         ALGORITHM_SESSION_ATTEST_1,
                                                         provisioning.privacyEnabled,
                                                         provisioning.keyManagementKey,
                                                         provisioning.clientTime,
                                                         provisioning.sessionLifeTime,
                                                         provisioning.serverSessionId,
                                                         provisioning.clientSessionId,
                                                         provisioning.issuerUri);
            }
        }
        return null;
    }

    static void abort(String message) {
        abort(message, SKSException.ERROR_OPTION);
    }

    static void abort(String message, int option) {
        throw new SKSException(message, option);
    }

    static void abort(Throwable e) {
        if (e instanceof SKSException) {
            throw (SKSException)e;
        }
        if (e instanceof GeneralSecurityException) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
        throw new SKSException(e);
    }

    void tearDownSession(Provisioning provisioning, Throwable e) {
        if (provisioning != null) {
            abortProvisioningSession(provisioning.provisioningHandle);
        }
        abort(e);
    }

    void tearDownSession(KeyEntry key, Throwable e) {
        tearDownSession(key == null ? null : key.owner, e);
    }

    Algorithm getEcType(ECKey ecKey) {
        for (String uri : supportedAlgorithms.keySet()) {
            ECParameterSpec ref = supportedAlgorithms.get(uri).ecParameterSpec;
            if (ref != null) {
                ECParameterSpec actual = ecKey.getParams();
                if (ref.getCofactor() == actual.getCofactor() &&
                    ref.getOrder().equals(actual.getOrder()) &&
                    ref.getCurve().equals(actual.getCurve()) &&
                    ref.getGenerator().equals(actual.getGenerator())) {
                    return supportedAlgorithms.get(uri);
                }
            }
        }
        return null;
    }

    String checkEcKeyCompatibility(ECKey ecKey, String keyId) {
        Algorithm ecType = getEcType(ecKey);
        if (ecType != null) {
            return ecType.jceName;
        }
        abort("Unsupported EC key algorithm for: " + keyId);
        return null;
    }

    int getEcPointLength(ECKey ecKey) throws GeneralSecurityException {
        Algorithm ecType = getEcType(ecKey);
        if (ecType != null) {
            return ecType.ecPointLength;
        }
        throw new GeneralSecurityException("Unsupported EC curve");
    }

    void checkRsaKeyCompatibility(RSAPublicKey publicKey, String keyId) {

        if (!SKS_RSA_EXPONENT_SUPPORT && !publicKey.getPublicExponent().equals(RSAKeyGenParameterSpec.F4)) {
            abort("Unsupported RSA exponent value for: " + keyId);
        }
        int rsaKeySize = getRsaKeySize(publicKey);
        boolean found = false;
        for (short keySize : SKS_DEFAULT_RSA_SUPPORT) {
            if (keySize == rsaKeySize) {
                found = true;
                break;
            }
        }
        if (!found) {
            abort("Unsupported RSA key size " + rsaKeySize + " for: " + keyId);
        }
    }

//#if ANDROID
    void coreCompatibilityCheck(KeyEntry keyEntry, PrivateKey privateKey){
        if (keyEntry.isRsa() ^ privateKey instanceof RSAKey) {
//#else
    void coreCompatibilityCheck(KeyEntry keyEntry){
        if (keyEntry.isRsa() ^ keyEntry.privateKey instanceof RSAKey) {
//#endif
            abort("RSA/EC mixup between public and private keys for: " + keyEntry.id);
        }
    }

    int getRsaKeySize(RSAKey rsaKey) {
        byte[] modblob = rsaKey.getModulus().toByteArray();
        return (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
    }

    @SuppressWarnings("fallthrough")
    void verifyPinPolicyCompliance(boolean forcedSetter,
                                   byte[] pinValue,
                                   PINPolicy pinPolicy,
                                   byte appUsage) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN length
        ///////////////////////////////////////////////////////////////////////////////////
        if (pinValue.length > pinPolicy.maxLength || pinValue.length < pinPolicy.minLength) {
            abort("PIN length error");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN syntax
        ///////////////////////////////////////////////////////////////////////////////////
        boolean upperalpha = false;
        boolean loweralpha = false;
        boolean number = false;
        boolean nonalphanum = false;
        for (int i = 0; i < pinValue.length; i++) {
            int c = pinValue[i];
            if (c >= 'A' && c <= 'Z') {
                upperalpha = true;
            } else if (c >= 'a' && c <= 'z') {
                loweralpha = true;
            } else if (c >= '0' && c <= '9') {
                number = true;
            } else {
                nonalphanum = true;
            }
        }
        if ((pinPolicy.format == PASSPHRASE_FORMAT_NUMERIC && (loweralpha || nonalphanum || upperalpha)) ||
            (pinPolicy.format == PASSPHRASE_FORMAT_ALPHANUMERIC && (loweralpha || nonalphanum))) {
            abort("PIN syntax error");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN patterns
        ///////////////////////////////////////////////////////////////////////////////////
        if ((pinPolicy.patternRestrictions & PIN_PATTERN_MISSING_GROUP) != 0) {
            if (!upperalpha || !number ||
                (pinPolicy.format == PASSPHRASE_FORMAT_STRING && (!loweralpha || !nonalphanum))) {
                abort("Missing character group in PIN");
            }
        }
        if ((pinPolicy.patternRestrictions & PIN_PATTERN_SEQUENCE) != 0) {
            byte c = pinValue[0];
            byte f = (byte) (pinValue[1] - c);
            boolean seq = (f == 1) || (f == -1);
            for (int i = 1; i < pinValue.length; i++) {
                if ((byte) (c + f) != pinValue[i]) {
                    seq = false;
                    break;
                }
                c = pinValue[i];
            }
            if (seq) {
                abort("PIN must not be a sequence");
            }
        }
        if ((pinPolicy.patternRestrictions & PIN_PATTERN_REPEATED) != 0) {
            for (int i = 0; i < pinValue.length; i++) {
                byte b = pinValue[i];
                for (int j = 0; j < pinValue.length; j++) {
                    if (j != i && b == pinValue[j]) {
                        abort("Repeated PIN character");
                    }
                }
            }
        }
        if ((pinPolicy.patternRestrictions & (PIN_PATTERN_TWO_IN_A_ROW | PIN_PATTERN_THREE_IN_A_ROW)) != 0) {
            int max = ((pinPolicy.patternRestrictions & PIN_PATTERN_TWO_IN_A_ROW) == 0) ? 3 : 2;
            byte c = pinValue[0];
            int sameCount = 1;
            for (int i = 1; i < pinValue.length; i++) {
                if (c == pinValue[i]) {
                    if (++sameCount == max) {
                        abort("PIN with " + max + " or more of same the character in a row");
                    }
                } else {
                    sameCount = 1;
                    c = pinValue[i];
                }
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that PIN grouping rules are followed
        ///////////////////////////////////////////////////////////////////////////////////
        for (KeyEntry keyEntry : keys.values()) {
            if (keyEntry.pinPolicy == pinPolicy) {
                boolean equal = Arrays.equals(keyEntry.pinValue, pinValue);
                if (forcedSetter && !equal) {
                    continue;
                }
                switch (pinPolicy.grouping) {
                    case PIN_GROUPING_SHARED:
                        if (!equal) {
                            abort("Grouping = \"shared\" requires identical PINs");
                        }
                        continue;

                    case PIN_GROUPING_UNIQUE:
                        if (equal ^ (appUsage == keyEntry.appUsage)) {
                            abort("Grouping = \"unique\" PIN error");
                        }
                        continue;

                    case PIN_GROUPING_SIGN_PLUS_STD:
                        if (((appUsage == APP_USAGE_SIGNATURE) ^ (keyEntry.appUsage == APP_USAGE_SIGNATURE)) ^ !equal) {
                            abort("Grouping = \"signature+standard\" PIN error");
                        }
                }
            }
        }
    }

    void testUpdatablePin(KeyEntry keyEntry, byte[] newPin) {
        if (!keyEntry.pinPolicy.userModifiable) {
            abort("PIN for key #" + keyEntry.keyHandle + " is not user modifiable", SKSException.ERROR_NOT_ALLOWED);
        }
        verifyPinPolicyCompliance(true, newPin, keyEntry.pinPolicy, keyEntry.appUsage);
    }

    void deleteEmptySession(Provisioning provisioning) {
        for (KeyEntry keyEntry : keys.values()) {
            if (keyEntry.owner == provisioning) {
                return;
            }
        }
        provisionings.remove(provisioning.provisioningHandle);
    }

    void localDeleteKey(KeyEntry keyEntry) {
        keys.remove(keyEntry.keyHandle);
        if (keyEntry.pinPolicy != null) {
            int pinPolicyHandle = keyEntry.pinPolicy.pinPolicyHandle;
            for (int handle : keys.keySet()) {
                if (handle == pinPolicyHandle) {
                    return;
                }
            }
            pinPolicies.remove(pinPolicyHandle);
            if (keyEntry.pinPolicy.pukPolicy != null) {
                int pukPolicyHandle = keyEntry.pinPolicy.pukPolicy.pukPolicyHandle;
                for (int handle : pinPolicies.keySet()) {
                    if (handle == pukPolicyHandle) {
                        return;
                    }
                }
                pukPolicies.remove(pukPolicyHandle);
            }
        }
    }

    Algorithm checkKeyAndAlgorithm(KeyEntry keyEntry, String inputAlgorithm, int expectedType) {
        Algorithm alg = getAlgorithm(inputAlgorithm);
        if ((alg.mask & expectedType) == 0) {
            abort("Algorithm does not match operation: " + 
                  inputAlgorithm, SKSException.ERROR_ALGORITHM);
        }
        if (((alg.mask & ALG_SYM_KEY) != 0) ^ keyEntry.isSymmetric()) {
            abort((keyEntry.isSymmetric() ? "S" : "As") + 
                  "ymmetric key #" + keyEntry.keyHandle + " is incompatible with: " +
                  inputAlgorithm, SKSException.ERROR_ALGORITHM);
        }
        if (keyEntry.isSymmetric()) {
            testAESKey(inputAlgorithm, keyEntry.symmetricKey, "#" + keyEntry.keyHandle);
        } else if (keyEntry.isRsa() ^ (alg.mask & ALG_RSA_KEY) != 0) {
            abort((keyEntry.isRsa() ? "RSA" : "EC") + " key #" + keyEntry.keyHandle + " is incompatible with: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
        }
        if (keyEntry.endorsedAlgorithms.isEmpty() || 
            keyEntry.endorsedAlgorithms.contains(inputAlgorithm)) {
            return alg;
        }
        abort("\"" + VAR_ENDORSED_ALGORITHMS + "\" for key #" + keyEntry.keyHandle + " does not include: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
        return null;    // For the compiler...
    }

    byte[] addArrays(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    void testAESKey(String algorithm, byte[] symmetricKey, String keyId) {
        Algorithm alg = getAlgorithm(algorithm);
        if ((alg.mask & ALG_SYM_ENC) != 0) {
            int l = symmetricKey.length;
            if (l == 16) l = ALG_SYML_128;
            else if (l == 24) l = ALG_SYML_192;
            else if (l == 32) l = ALG_SYML_256;
            else l = 0;
            if ((l & alg.mask) == 0) {
                abort("Key " + keyId + " has wrong size (" + symmetricKey.length + ") for algorithm: " + algorithm);
            }
        }
    }

    Algorithm getAlgorithm(String algorithmUri) {
        Algorithm alg = supportedAlgorithms.get(algorithmUri);
        if (alg == null) {
            abort("Unsupported algorithm: " + algorithmUri, SKSException.ERROR_ALGORITHM);
        }
        return alg;
    }

    void verifyExportDeleteProtection(byte actualProtection, byte minProtectionVal, Provisioning provisioning) {
        if (actualProtection >= minProtectionVal && actualProtection <= EXPORT_DELETE_PROTECTION_PUK) {
            abort("Protection object lacks a PIN or PUK object");
        }
    }

    void addUpdateKeyOrCloneKeyProtection(int keyHandle,
                                          int targetKeyHandle,
                                          byte[] authorization,
                                          byte[] mac,
                                          boolean update) {
        KeyEntry newKey = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get open key and associated provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            newKey = getOpenKey(keyHandle);
            Provisioning provisioning = newKey.owner;
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key to be updated/cloned
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry targetKeyEntry = provisioning.getTargetKey(targetKeyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Perform some "sanity" tests
            ///////////////////////////////////////////////////////////////////////////////////
            if (newKey.pinPolicy != null || newKey.devicePinProtection) {
                abort("Updated/cloned keys must not define PIN protection");
            }
            if (update) {
                if (targetKeyEntry.appUsage != newKey.appUsage) {
                    abort("Updated keys must have the same \"" + VAR_APP_USAGE + "\" as the target key");
                }
            } else {
                ///////////////////////////////////////////////////////////////////////////////////
                // Cloned keys must share the PIN of its parent
                ///////////////////////////////////////////////////////////////////////////////////
                if (targetKeyEntry.pinPolicy != null && targetKeyEntry.pinPolicy.grouping != PIN_GROUPING_SHARED) {
                    abort("A cloned key protection must have PIN grouping=\"shared\"");
                }
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC and target key data
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = newKey.getEeCertMacBuilder(update ? METHOD_POST_UPDATE_KEY : METHOD_POST_CLONE_KEY_PROTECTION);
            targetKeyEntry.validateTargetKeyReference(verifier, mac, authorization, provisioning);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Put the operation in the post-op buffer used by "closeProvisioningSession"
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.addPostProvisioningObject(targetKeyEntry, newKey, update);
//#if ANDROID
            logCertificateOperation(targetKeyEntry, update ? "post-updated" : "post-cloned");
//#endif
        } catch (Exception e) {
            tearDownSession(newKey, e);
        }
    }


    void addUnlockKeyOrDeleteKey(int provisioningHandle,
                                 int targetKeyHandle,
                                 byte[] authorization,
                                 byte[] mac,
                                 boolean delete) {
        Provisioning provisioning = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning = getOpenProvisioningSession(provisioningHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key to be deleted or unlocked
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry targetKeyEntry = provisioning.getTargetKey(targetKeyHandle);
            if (!delete && targetKeyEntry.pinPolicy == null) {
                abort("Key #" + targetKeyHandle + " is not PIN protected");
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC and target key data
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = provisioning.getMacBuilderForMethodCall(delete ?
                                                          METHOD_POST_DELETE_KEY : METHOD_POST_UNLOCK_KEY);
            targetKeyEntry.validateTargetKeyReference(verifier, mac, authorization, provisioning);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Put the operation in the post-op buffer used by "closeProvisioningSession"
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.addPostProvisioningObject(targetKeyEntry, null, delete);
//#if ANDROID
            logCertificateOperation(targetKeyEntry, delete ? "post-deleted" : "post-unlocked");
//#endif
        } catch (Exception e) {
            tearDownSession(provisioning, e);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               unlockKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void unlockKey(int keyHandle, byte[] authorization) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PUK
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPuk(authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Reset PIN error counter(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.setErrorCounter((short) 0);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               changePin                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void changePin(int keyHandle,
                                       byte[] authorization,
                                       byte[] newPin) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify old PIN
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPin(authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Test new PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePin(keyEntry, newPin);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Set PIN value(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.updatePin(newPin);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                                 setPin                                     //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void setPin(int keyHandle,
                                    byte[] authorization,
                                    byte[] newPin) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PUK
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPuk(authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Test new PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePin(keyEntry, newPin);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Set PIN value(s) and unlock associated key(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.updatePin(newPin);
        keyEntry.setErrorCounter((short) 0);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               deleteKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void deleteKey(int keyHandle, byte[] authorization) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that authorization matches the declaration
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.authorizeExportOrDeleteOperation(keyEntry.deleteProtection, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Delete key and optionally the entire provisioning object (if empty)
        ///////////////////////////////////////////////////////////////////////////////////
//#if ANDROID
        try {
            HardwareKeyStore.deleteKey(keyEntry.getKeyId());
        } catch (Exception e) {
            abort(e);
        }
//#endif
        localDeleteKey(keyEntry);
        deleteEmptySession(keyEntry.owner);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               exportKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] exportKey(int keyHandle, byte[] authorization) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that authorization matches the declaration
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.authorizeExportOrDeleteOperation(keyEntry.exportProtection, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Mark as "copied" locally
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.keyBackup |= KeyProtectionInfo.KEYBACKUP_EXPORTED;

        ///////////////////////////////////////////////////////////////////////////////////
        // Export key in raw unencrypted format
        ///////////////////////////////////////////////////////////////////////////////////
//#if ANDROID
        return keyEntry.isSymmetric() ? 
                keyEntry.symmetricKey : keyEntry.exportablePrivateKey.getEncoded();
//#else
        return keyEntry.isSymmetric() ?
                keyEntry.symmetricKey : keyEntry.privateKey.getEncoded();
//#endif
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              setProperty                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void setProperty(int keyHandle,
                                         String type,
                                         String name,
                                         String value) {
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key (which must belong to an already fully provisioned session)
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = getStdKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Lookup the extension(s) bound to the key
            ///////////////////////////////////////////////////////////////////////////////////
            ExtObject extObj = keyEntry.extensions.get(type);
            if (extObj == null || extObj.subType != SUB_TYPE_PROPERTY_BAG) {
                abort("No such \"" + VAR_PROPERTY_BAG + "\" : " + type);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Found, now look for the property name and update the associated value
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] binName = getBinary(name);
            byte[] binValue = getBinary(value);
            int i = 0;
            while (i < extObj.extensionData.length) {
                int nameLen = getShort(extObj.extensionData, i);
                i += 2;
                byte[] pname = Arrays.copyOfRange(extObj.extensionData, i, nameLen + i);
                i += nameLen;
                int valueLen = getShort(extObj.extensionData, i + 1);
                if (Arrays.equals(binName, pname)) {
                    if (extObj.extensionData[i] != 0x01) {
                        abort("\"" + VAR_PROPERTY + "\" not writable: " + name, SKSException.ERROR_NOT_ALLOWED);
                    }
                    extObj.extensionData = 
                            addArrays(addArrays(Arrays.copyOfRange(extObj.extensionData, 0, ++i),
                            addArrays(new byte[]{(byte) (binValue.length >> 8), (byte) binValue.length}, binValue)),
                            Arrays.copyOfRange(extObj.extensionData, i + valueLen + 2, extObj.extensionData.length));
                    return;
                }
                i += valueLen + 3;
            }
            abort("\"" + VAR_PROPERTY + "\" not found: " + name);
        } catch (IOException e) {
            throw new SKSException(e);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized Extension getExtension(int keyHandle, String type) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Lookup the extension(s) bound to the key
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject extObj = keyEntry.extensions.get(type);
        if (extObj == null) {
            abort("No such extension: " + type + " for key #" + keyHandle);
        }
        return new Extension(extObj.subType, extObj.qualifier, extObj.extensionData);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         asymmetricKeyDecrypt                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] asymmetricKeyDecrypt(int keyHandle,
                                                    String algorithm,
                                                    byte[] parameters,
                                                    boolean biometricAuth,
                                                    byte[] authorization,
                                                    byte[] data) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Authorize
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.authorize(biometricAuth, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the encryption algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(keyEntry, algorithm, ALG_ASYM_ENC);
        if (parameters != null)  { // Only support basic RSA yet...
             abort("\"" + VAR_PARAMETERS + "\" for key #" + keyHandle + " do not match algorithm");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            Cipher cipher = Cipher.getInstance(alg.jceName);
            if ((alg.mask & ALG_MFG1_256) != 0) {
                cipher.init(Cipher.DECRYPT_MODE, keyEntry.MACRO_GET_PRIVATEKEY,
                    new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, keyEntry.MACRO_GET_PRIVATEKEY);
            }
            return cipher.doFinal(data);
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                                signData                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] signData(int keyHandle,
                                        String algorithm,
                                        byte[] parameters,
                                        boolean biometricAuth,
                                        byte[] authorization,
                                        byte[] data) {
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key (which must belong to an already fully provisioned session)
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = getStdKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Authorize
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.authorize(biometricAuth, authorization);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Enforce the data limit
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.checkCryptoDataSize(data);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check that the signature algorithm is known and applicable
            ///////////////////////////////////////////////////////////////////////////////////
            Algorithm alg = checkKeyAndAlgorithm(keyEntry, algorithm, ALG_ASYM_SGN);
            if (parameters != null)  // Only supports non-parameterized operations yet...
            {
                abort("\"" + VAR_PARAMETERS + "\" for key #" + keyHandle + " do not match algorithm");
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, perform operation
            ///////////////////////////////////////////////////////////////////////////////////
            return new SignatureWrapper(alg.jceName, keyEntry.MACRO_GET_PRIVATEKEY).update(data).sign();
        } catch (Exception e) {
            abort(e);
            return null;    // For the compiler...
        }

    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             keyAgreement                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] keyAgreement(int keyHandle,
                                            String algorithm,
                                            byte[] parameters,
                                            boolean biometricAuth,
                                            byte[] authorization,
                                            ECPublicKey publicKey) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Authorize
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.authorize(biometricAuth, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key agreement algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(keyEntry, algorithm, ALG_ASYM_KA);
        if (parameters != null)  // Only support external KDFs yet...
        {
            abort("\"" + VAR_PARAMETERS + "\" for key #" + keyHandle + " do not match algorithm");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key type matches the algorithm
        ///////////////////////////////////////////////////////////////////////////////////
        checkEcKeyCompatibility(publicKey, "\"" + VAR_PUBLIC_KEY + "\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            KeyAgreement key_agreement = KeyAgreement.getInstance(alg.jceName);
            key_agreement.init(keyEntry.MACRO_GET_PRIVATEKEY);
            key_agreement.doPhase(publicKey, true);
            return key_agreement.generateSecret();
        } catch (Exception e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          symmetricKeyEncrypt                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] symmetricKeyEncrypt(int keyHandle,
                                                   String algorithm,
                                                   boolean mode,
                                                   byte[] parameters,
                                                   boolean biometricAuth,
                                                   byte[] authorization,
                                                   byte[] data) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Authorize
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.authorize(biometricAuth, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.checkCryptoDataSize(data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check the key and then check that the algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(keyEntry, algorithm, ALG_SYM_ENC);
        if ((alg.mask & ALG_IV_REQ) == 0 || (alg.mask & ALG_IV_INT) != 0) {
            if (parameters != null) {
                abort("\"" + VAR_PARAMETERS + "\" does not apply to: " + algorithm);
            }
        } else if (parameters == null || parameters.length != 16) {
            abort("\"" + VAR_PARAMETERS + "\" must be 16 bytes for: " + algorithm);
        }
        if ((!mode || (alg.mask & ALG_AES_PAD) != 0) && data.length % 16 != 0) {
            abort("Data must be a multiple of 16 bytes for: " + algorithm + (mode ? " encryption" : " decryption"));
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            Cipher crypt = Cipher.getInstance(alg.jceName);
            SecretKeySpec sk = new SecretKeySpec(keyEntry.symmetricKey, "AES");
            int jceMode = mode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
            if ((alg.mask & ALG_IV_INT) != 0) {
                parameters = new byte[16];
                if (mode) {
                    new SecureRandom().nextBytes(parameters);
                } else {
                    byte[] temp = new byte[data.length - 16];
                    System.arraycopy(data, 0, parameters, 0, 16);
                    System.arraycopy(data, 16, temp, 0, temp.length);
                    data = temp;
                }
            }
            if (parameters == null) {
                crypt.init(jceMode, sk);
            } else {
                crypt.init(jceMode, sk, new IvParameterSpec(parameters));
            }
            data = crypt.doFinal(data);
            return (mode && (alg.mask & ALG_IV_INT) != 0) ? addArrays(parameters, data) : data;
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               performHmac                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] performHmac(int keyHandle,
                                           String algorithm,
                                           byte[] parameters,
                                           boolean biometricAuth,
                                           byte[] authorization,
                                           byte[] data) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Authorize
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.authorize(biometricAuth, authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.checkCryptoDataSize(data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check the key and then check that the algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(keyEntry, algorithm, ALG_HMAC);
        if (parameters != null) {
            abort("\"" + VAR_PARAMETERS + "\" does not apply to: " + algorithm);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            Mac mac = Mac.getInstance(alg.jceName);
            mac.init(new SecretKeySpec(keyEntry.symmetricKey, "RAW"));
            return mac.doFinal(data);
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getDeviceInfo                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized DeviceInfo getDeviceInfo() {
        return new DeviceInfo(SKS_API_LEVEL,
                              (byte) (DeviceInfo.LOCATION_EMBEDDED | DeviceInfo.TYPE_SOFTWARE),
                              SKS_UPDATE_URL,
                              SKS_VENDOR_NAME,
                              SKS_VENDOR_DESCRIPTION,
                              deviceCertificatePath,
                              supportedAlgorithms.keySet().toArray(new String[0]),
                              MAX_LENGTH_CRYPTO_DATA,
                              MAX_LENGTH_EXTENSION_DATA,
                              SKS_DEVICE_PIN_SUPPORT,
                              SKS_BIOMETRIC_SUPPORT);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             updateFirmware                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public String updateFirmware(byte[] chunk) {
        throw new SKSException("Updates are not supported", SKSException.ERROR_NOT_ALLOWED);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              enumerateKeys                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized EnumeratedKey enumerateKeys(int keyHandle) {
        if (keyHandle == EnumeratedKey.INIT_ENUMERATION) {
            return getKey(keys.values().iterator());
        }
        Iterator<KeyEntry> list = keys.values().iterator();
        while (list.hasNext()) {
            if (list.next().keyHandle == keyHandle) {
                return getKey(list);
            }
        }
        return null;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          getKeyProtectionInfo                              //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized KeyProtectionInfo getKeyProtectionInfo(int keyHandle) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Find the protection data objects that are not stored in the key entry
        ///////////////////////////////////////////////////////////////////////////////////
        byte protectionStatus = KeyProtectionInfo.PROTSTAT_NO_PIN;
        byte pukFormat = 0;
        short pukRetryLimit = 0;
        short pukErrorCount = 0;
        boolean userDefined = false;
        boolean userModifiable = false;
        byte format = 0;
        short retryLimit = 0;
        byte grouping = 0;
        byte patternRestrictions = 0;
        short minLength = 0;
        short maxLength = 0;
        byte inputMethod = 0;
        if (keyEntry.devicePinProtection) {
            protectionStatus = KeyProtectionInfo.PROTSTAT_DEVICE_PIN;
        } else if (keyEntry.pinPolicy != null) {
            protectionStatus = KeyProtectionInfo.PROTSTAT_PIN_PROTECTED;
            if (keyEntry.errorCount >= keyEntry.pinPolicy.retryLimit) {
                protectionStatus |= KeyProtectionInfo.PROTSTAT_PIN_BLOCKED;
            }
            if (keyEntry.pinPolicy.pukPolicy != null) {
                pukFormat = keyEntry.pinPolicy.pukPolicy.format;
                pukRetryLimit = keyEntry.pinPolicy.pukPolicy.retryLimit;
                pukErrorCount = keyEntry.pinPolicy.pukPolicy.errorCount;
                protectionStatus |= KeyProtectionInfo.PROTSTAT_PUK_PROTECTED;
                if (keyEntry.pinPolicy.pukPolicy.errorCount >= keyEntry.pinPolicy.pukPolicy.retryLimit &&
                        keyEntry.pinPolicy.pukPolicy.retryLimit > 0) {
                    protectionStatus |= KeyProtectionInfo.PROTSTAT_PUK_BLOCKED;
                }
            }
            userDefined = keyEntry.pinPolicy.userDefined;
            userModifiable = keyEntry.pinPolicy.userModifiable;
            format = keyEntry.pinPolicy.format;
            retryLimit = keyEntry.pinPolicy.retryLimit;
            grouping = keyEntry.pinPolicy.grouping;
            patternRestrictions = keyEntry.pinPolicy.patternRestrictions;
            minLength = keyEntry.pinPolicy.minLength;
            maxLength = keyEntry.pinPolicy.maxLength;
            inputMethod = keyEntry.pinPolicy.inputMethod;
        }
        return new KeyProtectionInfo(protectionStatus,
                                     pukFormat,
                                     pukRetryLimit,
                                     pukErrorCount,
                                     userDefined,
                                     userModifiable,
                                     format,
                                     retryLimit,
                                     grouping,
                                     patternRestrictions,
                                     minLength,
                                     maxLength,
                                     inputMethod,
                                     keyEntry.errorCount,
                                     keyEntry.enablePinCaching,
                                     keyEntry.biometricProtection,
                                     keyEntry.exportProtection,
                                     keyEntry.deleteProtection,
                                     keyEntry.keyBackup);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            getKeyAttributes                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized KeyAttributes getKeyAttributes(int keyHandle) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Return core key entry metadata
        ///////////////////////////////////////////////////////////////////////////////////
        return new KeyAttributes((short) (keyEntry.isSymmetric() ? keyEntry.symmetricKey.length : 0),
                                 keyEntry.certificatePath,
                                 keyEntry.appUsage,
                                 keyEntry.friendlyName,
                                 keyEntry.endorsedAlgorithms.toArray(new String[0]),
                                 keyEntry.extensions.keySet().toArray(new String[0]));
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           updateKeyManagementKey                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public void updateKeyManagementKey(int provisioningHandle,
                                       PublicKey keyManagementKey,
                                       byte[] authorization) {
        try {
            Provisioning provisioning = getClosedProvisioningSession(provisioningHandle);
            if (provisioning.keyManagementKey == null) {
                abort("Session is not updatable: " + provisioningHandle, SKSException.ERROR_NOT_ALLOWED);
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify KMK signature
            ///////////////////////////////////////////////////////////////////////////////////
            if (!provisioning.verifyKeyManagementKeyAuthorization(KMK_ROLL_OVER_AUTHORIZATION,
                                                                  keyManagementKey.getEncoded(),
                                                                  authorization)) {
                abort("\"" + VAR_AUTHORIZATION + "\" signature did not verify for session: " + provisioningHandle);
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Success, update KeyManagementKey
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.keyManagementKey = keyManagementKey;
//#if ANDROID
            Log.i(SKS_DEBUG, "Updated KMK");
//#endif
        } catch (Exception e) {
            abort(e);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       enumerateProvisioningSessions                        //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized EnumeratedProvisioningSession enumerateProvisioningSessions(int provisioningHandle,
                                                                                    boolean provisioningState) {
        if (provisioningHandle == EnumeratedProvisioningSession.INIT_ENUMERATION) {
            return getProvisioning(provisionings.values().iterator(), provisioningState);
        }
        Iterator<Provisioning> list = provisionings.values().iterator();
        while (list.hasNext()) {
            if (list.next().provisioningHandle == provisioningHandle) {
                return getProvisioning(list, provisioningState);
            }
        }
        return null;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getKeyHandle                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized int getKeyHandle(int provisioningHandle, String id) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession(provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Look for key with virtual ID
        ///////////////////////////////////////////////////////////////////////////////////
        for (KeyEntry keyEntry : keys.values()) {
            if (keyEntry.owner == provisioning && keyEntry.id.equals(id)) {
                return keyEntry.keyHandle;
            }
        }
        abort("Key " + id + " missing");
        return 0;    // For the compiler...
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             postDeleteKey                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postDeleteKey(int provisioningHandle,
                                           int targetKeyHandle,
                                           byte[] authorization,
                                           byte[] mac) {
        addUnlockKeyOrDeleteKey(provisioningHandle, targetKeyHandle, authorization, mac, true);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             postUnlockKey                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postUnlockKey(int provisioningHandle,
                                           int targetKeyHandle,
                                           byte[] authorization,
                                           byte[] mac) {
        addUnlockKeyOrDeleteKey(provisioningHandle, targetKeyHandle, authorization, mac, false);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          postCloneKeyProtection                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postCloneKeyProtection(int keyHandle,
                                                    int targetKeyHandle,
                                                    byte[] authorization,
                                                    byte[] mac) {
        addUpdateKeyOrCloneKeyProtection(keyHandle, targetKeyHandle, authorization, mac, false);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              postUpdateKey                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void postUpdateKey(int keyHandle,
                                           int targetKeyHandle,
                                           byte[] authorization,
                                           byte[] mac) {
        addUpdateKeyOrCloneKeyProtection(keyHandle, targetKeyHandle, authorization, mac, true);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         abortProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void abortProvisioningSession(int provisioningHandle) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession(provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Wind it down
        ///////////////////////////////////////////////////////////////////////////////////
        deleteObject(keys, provisioning);
        deleteObject(pinPolicies, provisioning);
        deleteObject(pukPolicies, provisioning);
        provisionings.remove(provisioningHandle);
//#if ANDROID
        Log.i(SKS_DEBUG, "Session ABORTED");
//#endif
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        closeProvisioningSession                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] closeProvisioningSession(int provisioningHandle,
                                                        byte[] nonce,
                                                        byte[] mac) {
        Provisioning provisioning = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning = getOpenProvisioningSession(provisioningHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = 
                    provisioning.getMacBuilderForMethodCall(METHOD_CLOSE_PROVISIONING_SESSION);
            verifier.addString(provisioning.clientSessionId);
            verifier.addString(provisioning.serverSessionId);
            verifier.addString(provisioning.issuerUri);
            verifier.addArray(nonce);
            provisioning.verifyMac(verifier, mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Generate the attestation in advance => checking SessionKeyLimit before "commit"
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder close_attestation = 
                    provisioning.getMacBuilderForMethodCall(KDF_DEVICE_ATTESTATION);
            close_attestation.addArray(nonce);
            byte[] attestation = close_attestation.getResult();
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Perform "sanity" checks on provisioned data
            ///////////////////////////////////////////////////////////////////////////////////
            for (String id : provisioning.names.keySet()) {
                if (!provisioning.names.get(id)) {
                    abort("Unreferenced object \"" + VAR_ID + "\" : " + id);
                }
            }
            provisioning.names.clear();
            for (KeyEntry keyEntry : keys.values()) {
                if (keyEntry.owner == provisioning) {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // A key provisioned in this session
                    ///////////////////////////////////////////////////////////////////////////////////
                    keyEntry.checkEECertificateAvailability();
    
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Check public versus private key match
                    ///////////////////////////////////////////////////////////////////////////////////
//#if ANDROID
                    coreCompatibilityCheck(keyEntry, keyEntry.MACRO_GET_PRIVATEKEY);
//#else
                    coreCompatibilityCheck(keyEntry);
//#endif
                    if (keyEntry.isEc() || keyEntry.isRsa()) {
                        String signatureAlgorithm = keyEntry.isRsa() ?
                                "NONEwithRSA" : "NONEwithECDSA";
                        Signature sign = Signature.getInstance(signatureAlgorithm);
                        sign.initSign(keyEntry.MACRO_GET_PRIVATEKEY);
                        sign.update(RSA_ENCRYPTION_OID);  // Any data could be used...
                        byte[] signedData = sign.sign();
                        Signature verify = Signature.getInstance(signatureAlgorithm);
                        verify.initVerify(keyEntry.publicKey);
                        verify.update(RSA_ENCRYPTION_OID);
                        if (!verify.verify(signedData)) {
                            abort("Public/private key mismatch for: " + keyEntry.id);
                        }
                    }
    
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Test that there are no collisions
                    ///////////////////////////////////////////////////////////////////////////////////
                    for (KeyEntry keyEntryTemp : keys.values()) {
                        if (keyEntryTemp.keyHandle != keyEntry.keyHandle && keyEntryTemp.certificatePath != null &&
                                keyEntryTemp.certificatePath[0].equals(keyEntry.certificatePath[0])) {
                            ///////////////////////////////////////////////////////////////////////////////////
                            // There was a conflict, ignore updates/deletes
                            ///////////////////////////////////////////////////////////////////////////////////
                            boolean collision = true;
                            for (PostProvisioningObject postOp : provisioning.postProvisioningObjects) {
                                if (postOp.targetKeyEntry == keyEntryTemp && postOp.updateOrDelete) {
                                    collision = false;
                                }
                            }
                            if (collision) {
                                abort("Duplicate certificate in \"setCertificatePath\" for: " + keyEntry.id);
                            }
                        }
                    }
    
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Check that possible endorsed algorithms match key material
                    ///////////////////////////////////////////////////////////////////////////////////
                    for (String algorithm : keyEntry.endorsedAlgorithms) {
                        Algorithm alg = getAlgorithm(algorithm);
                        if ((alg.mask & ALG_NONE) == 0) {
                            ///////////////////////////////////////////////////////////////////////////////////
                            // A non-null endorsed algorithm found.  Symmetric or asymmetric key?
                            ///////////////////////////////////////////////////////////////////////////////////
                            if (((alg.mask & ALG_SYM_KEY) == 0) ^ keyEntry.isSymmetric()) {
                                if (keyEntry.isSymmetric()) {
                                    ///////////////////////////////////////////////////////////////////////////////////
                                    // Symmetric. AES algorithms only operates on 128, 192, and 256 bit keys
                                    ///////////////////////////////////////////////////////////////////////////////////
                                    testAESKey(algorithm, keyEntry.symmetricKey, keyEntry.id);
                                    continue;
                                } else {
                                    ///////////////////////////////////////////////////////////////////////////////////
                                    // Asymmetric.  Check that algorithms match RSA or EC
                                    ///////////////////////////////////////////////////////////////////////////////////
                                    if (((alg.mask & ALG_RSA_KEY) == 0) ^ keyEntry.isRsa()) {
                                        continue;
                                    }
                                }
                            }
                            abort((keyEntry.isSymmetric() ? 
                                    "Symmetric" : keyEntry.isRsa() ? "RSA" : "EC") +
                                    " key " + keyEntry.id + " does not match algorithm: " + algorithm);
                        }
                    }
                }
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Post provisioning 1: Check that all the target keys are still there...
            ///////////////////////////////////////////////////////////////////////////////////
            for (PostProvisioningObject postOp : provisioning.postProvisioningObjects) {
                provisioning.getTargetKey(postOp.targetKeyEntry.keyHandle);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Post provisioning 2: Perform operations
            ///////////////////////////////////////////////////////////////////////////////////
            for (PostProvisioningObject postOp : provisioning.postProvisioningObjects) {
                KeyEntry keyEntry = postOp.targetKeyEntry;
                if (postOp.newKey == null) {
                    if (postOp.updateOrDelete) {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // postDeleteKey
                        ///////////////////////////////////////////////////////////////////////////////////
                        localDeleteKey(keyEntry);
                    } else {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // postUnlockKey 
                        ///////////////////////////////////////////////////////////////////////////////////
                        keyEntry.setErrorCounter((short) 0);
                        if (keyEntry.pinPolicy.pukPolicy != null) {
                            keyEntry.pinPolicy.pukPolicy.errorCount = 0;
                        }
                    }
                } else {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Inherit protection data from the old key but nothing else
                    ///////////////////////////////////////////////////////////////////////////////////
                    postOp.newKey.pinPolicy = keyEntry.pinPolicy;
                    postOp.newKey.pinValue = keyEntry.pinValue;
                    postOp.newKey.errorCount = keyEntry.errorCount;
                    postOp.newKey.devicePinProtection = keyEntry.devicePinProtection;
    
                    if (postOp.updateOrDelete) {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // postUpdateKey. Store new key in the place of the old
                        ///////////////////////////////////////////////////////////////////////////////////
                        keys.put(keyEntry.keyHandle, postOp.newKey);
    
                        ///////////////////////////////////////////////////////////////////////////////////
                        // Remove space occupied by the new key and restore old key handle
                        ///////////////////////////////////////////////////////////////////////////////////
//#if ANDROID
                        // In Android updates are slightly more fuzzy...
                        HardwareKeyStore.deleteKey(keyEntry.getKeyId());
                        postOp.newKey.remappedKeyHandle = postOp.newKey.keyHandle;
//#endif
                        keys.remove(postOp.newKey.keyHandle);
                        postOp.newKey.keyHandle = keyEntry.keyHandle;
                    }
                }
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Post provisioning 3: Take ownership of managed keys and their associates
            ///////////////////////////////////////////////////////////////////////////////////
            for (PostProvisioningObject postOp : provisioning.postProvisioningObjects) {
                Provisioning oldOwner = postOp.targetKeyEntry.owner;
                if (oldOwner == provisioning) {
                    continue;
                }
                for (KeyEntry keyEntry : keys.values()) {
                    if (keyEntry.owner == oldOwner) {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // There was a key that required changed ownership
                        ///////////////////////////////////////////////////////////////////////////////////
                        keyEntry.owner = provisioning;
                        if (keyEntry.pinPolicy != null) {
                            ///////////////////////////////////////////////////////////////////////////////
                            // Which also had a PIN policy...
                            ///////////////////////////////////////////////////////////////////////////////
                            keyEntry.pinPolicy.owner = provisioning;
                            if (keyEntry.pinPolicy.pukPolicy != null) {
                                ///////////////////////////////////////////////////////////////////////////
                                // Which in turn had a PUK policy...
                                ///////////////////////////////////////////////////////////////////////////
                                keyEntry.pinPolicy.pukPolicy.owner = provisioning;
                            }
                        }
                    }
                }
                provisionings.remove(oldOwner.provisioningHandle);  // OK to perform also if already done
            }
            provisioning.postProvisioningObjects.clear();  // No need to save
    
            ///////////////////////////////////////////////////////////////////////////////////
            // If there are no keys associated with the session we just delete it
            ///////////////////////////////////////////////////////////////////////////////////
            deleteEmptySession(provisioning);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // We are done, close the show for this time
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.open = false;
//#if ANDROID
            Log.i(SKS_DEBUG, "Session CLOSED");
//#endif
            return attestation;
        } catch (Exception e) {
            tearDownSession(provisioning, e);
            return null;
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        createProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized ProvisioningSession createProvisioningSession(String sessionKeyAlgorithm,
                                                                      boolean privacyEnabled,
                                                                      String serverSessionId,
                                                                      ECPublicKey serverEphemeralKey,
                                                                      String issuerUri,
                                                                      PublicKey keyManagementKey, // May be null
                                                                      int clientTime,
                                                                      short sessionLifeTime,
                                                                      short sessionKeyLimit,
                                                                      byte[] serverCertificate) {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check provisioning session algorithm compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (!sessionKeyAlgorithm.equals(ALGORITHM_SESSION_ATTEST_1)) {
            abort("Unknown \"" + VAR_SESSION_KEY_ALGORITHM + "\" : " + sessionKeyAlgorithm);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check issuerUri
        ///////////////////////////////////////////////////////////////////////////////////
        if (issuerUri.length() == 0 || issuerUri.length() > MAX_LENGTH_URI) {
            abort("\"" + VAR_ISSUER_URI + "\" length error: " + issuerUri.length());
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check server ECDH key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        String jceName = checkEcKeyCompatibility(serverEphemeralKey, "\"" + VAR_SERVER_EPHEMERAL_KEY + "\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Check optional key management key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (keyManagementKey != null) {
            if (keyManagementKey instanceof RSAKey) {
                checkRsaKeyCompatibility((RSAPublicKey) keyManagementKey,
                                         "\"" + VAR_KEY_MANAGEMENT_KEY + "\"");
            } else {
                checkEcKeyCompatibility((ECPublicKey) keyManagementKey,
                                        "\"" + VAR_KEY_MANAGEMENT_KEY + "\"");
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ServerSessionID
        ///////////////////////////////////////////////////////////////////////////////////
        checkIdSyntax(serverSessionId, VAR_SERVER_SESSION_ID);

        ///////////////////////////////////////////////////////////////////////////////////
        // Create ClientSessionID
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] random = new byte[MAX_LENGTH_ID_TYPE];
        new SecureRandom().nextBytes(random);
        StringBuilder clientSessionIdBuffer = new StringBuilder();
        for (byte b : random) {
            clientSessionIdBuffer.append(BASE64_URL[b & 0x3F]);
        }
        String clientSessionId = clientSessionIdBuffer.toString();

        ///////////////////////////////////////////////////////////////////////////////////
        // Prepare for the big crypto...
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] attestation = null;
        byte[] sessionKey = null;
        ECPublicKey clientEphemeralKey = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Create client ephemeral key
            ///////////////////////////////////////////////////////////////////////////////////
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec(jceName);
            generator.initialize(eccgen, new SecureRandom());
            KeyPair kp = generator.generateKeyPair();
            clientEphemeralKey = (ECPublicKey) kp.getPublic();

            ///////////////////////////////////////////////////////////////////////////////////
            // Apply the SP800-56A ECC CDH primitive
            ///////////////////////////////////////////////////////////////////////////////////
            KeyAgreement key_agreement = KeyAgreement.getInstance("ECDH");
            key_agreement.init(kp.getPrivate());
            key_agreement.doPhase(serverEphemeralKey, true);
            byte[] Z = key_agreement.generateSecret();

            ///////////////////////////////////////////////////////////////////////////////////
            // Use a custom KDF
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder kdf = new MacBuilder(Z);
            kdf.addString(clientSessionId);
            kdf.addString(serverSessionId);
            kdf.addString(issuerUri);
            kdf.addArray(getDeviceID(privacyEnabled));
            sessionKey = kdf.getResult();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create the Attestation
            ///////////////////////////////////////////////////////////////////////////////////
            ByteWriter attestationCreator = privacyEnabled  ? 
                                 new MacBuilder(sessionKey) : new AttestationSignatureGenerator();
            attestationCreator.addString(clientSessionId);
            attestationCreator.addString(serverSessionId);
            attestationCreator.addString(issuerUri);
            attestationCreator.addArray(getDeviceID(privacyEnabled));
            attestationCreator.addString(sessionKeyAlgorithm);
            attestationCreator.addBool(privacyEnabled);
            attestationCreator.addArray(serverEphemeralKey.getEncoded());
            attestationCreator.addArray(clientEphemeralKey.getEncoded());
            attestationCreator.addArray(keyManagementKey == null ? ZERO_LENGTH_ARRAY : keyManagementKey.getEncoded());
            attestationCreator.addInt(clientTime);
            attestationCreator.addShort(sessionLifeTime);
            attestationCreator.addShort(sessionKeyLimit);
            attestationCreator.addArray(serverCertificate);
            attestation = attestationCreator.getResult();
        } catch (Exception e) {
            abort(e);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // We did it!
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning p = new Provisioning();
        p.privacyEnabled = privacyEnabled;
        p.serverSessionId = serverSessionId;
        p.clientSessionId = clientSessionId;
        p.issuerUri = issuerUri;
        p.sessionKey = sessionKey;
        p.keyManagementKey = keyManagementKey;
        p.clientTime = clientTime;
        p.sessionLifeTime = sessionLifeTime;
        p.sessionKeyLimit = sessionKeyLimit;
//#if ANDROID
        Log.i(SKS_DEBUG, "Session CREATED");
//#endif
        return new ProvisioningSession(p.provisioningHandle,
                                       clientSessionId,
                                       attestation,
                                       clientEphemeralKey);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              addExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void addExtension(int keyHandle,
                                          String type,
                                          byte subType,
                                          String qualifier,
                                          byte[] extensionData,
                                          byte[] mac) {
        KeyEntry keyEntry = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key and associated provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry = getOpenKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check for duplicates and length errors
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.owner.rangeTest(subType, SUB_TYPE_EXTENSION, SUB_TYPE_LOGOTYPE, VAR_SUB_TYPE);
            if (type.length() == 0 || type.length() > MAX_LENGTH_URI) {
                abort("URI length error: " + type.length());
            }
            if (keyEntry.extensions.get(type) != null) {
                abort("Duplicate \"" + VAR_TYPE + "\" : " + type);
            }
            if (extensionData.length > (subType == SUB_TYPE_ENCRYPTED_EXTENSION ?
                    MAX_LENGTH_EXTENSION_DATA + AES_CBC_PKCS5_PADDING : MAX_LENGTH_EXTENSION_DATA)) {
                abort("Extension data exceeds " + MAX_LENGTH_EXTENSION_DATA + " bytes");
            }
            byte[] binQualifier = getBinary(qualifier);
            if (((subType == SUB_TYPE_LOGOTYPE) ^ (binQualifier.length != 0)) || binQualifier.length > MAX_LENGTH_QUALIFIER) {
                abort("\"" + VAR_QUALIFIER + "\" length error");
            }
            ///////////////////////////////////////////////////////////////////////////////////
            // Property bags are checked for not being empty or incorrectly formatted
            ///////////////////////////////////////////////////////////////////////////////////
            if (subType == SUB_TYPE_PROPERTY_BAG) {
                int i = 0;
                do {
                    if (i > extensionData.length - 5 || getShort(extensionData, i) == 0 ||
                            (i += getShort(extensionData, i) + 2) > extensionData.length - 3 ||
                            ((extensionData[i++] & 0xFE) != 0) ||
                            (i += getShort(extensionData, i) + 2) > extensionData.length) {
                        abort("\"" + VAR_PROPERTY_BAG + "\" format error: " + type);
                    }
                }
                while (i != extensionData.length);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = keyEntry.getEeCertMacBuilder(METHOD_ADD_EXTENSION);
            verifier.addString(type);
            verifier.addByte(subType);
            verifier.addArray(binQualifier);
            verifier.addBlob(extensionData);
            keyEntry.owner.verifyMac(verifier, mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Succeeded, create object
            ///////////////////////////////////////////////////////////////////////////////////
            ExtObject extension = new ExtObject();
            extension.subType = subType;
            extension.qualifier = qualifier;
            extension.extensionData = (subType == SUB_TYPE_ENCRYPTED_EXTENSION) ?
                    keyEntry.owner.decrypt(extensionData) : extensionData;
            keyEntry.extensions.put(type, extension);
//#if ANDROID
            logCertificateOperation(keyEntry, "extension '" + type + "'");
//#endif
        } catch (Exception e) {
            tearDownSession(keyEntry, e);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            importPrivateKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void importPrivateKey(int keyHandle,
                                              byte[] encryptedKey,
                                              byte[] mac) {
        KeyEntry keyEntry = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key and associated provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry = getOpenKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check for key length errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (encryptedKey.length > (MAX_LENGTH_CRYPTO_DATA + AES_CBC_PKCS5_PADDING)) {
                abort("Private key: " + keyEntry.id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = keyEntry.getEeCertMacBuilder(METHOD_IMPORT_PRIVATE_KEY);
            verifier.addArray(encryptedKey);
            keyEntry.owner.verifyMac(verifier, mac);
    
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Mark as "copied" by the server
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.setAndVerifyServerBackupFlag();
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Decrypt and store private key
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] pkcs8PrivateKey = keyEntry.owner.decrypt(encryptedKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8PrivateKey);

            ///////////////////////////////////////////////////////////////////////////////////
            // Bare-bones ASN.1 decoding to find out if it is RSA or EC 
            ///////////////////////////////////////////////////////////////////////////////////
            boolean rsaFlag = false;
            for (int j = 8; j < 11; j++) {
                rsaFlag = true;
                for (int i = 0; i < RSA_ENCRYPTION_OID.length; i++) {
                    if (pkcs8PrivateKey[j + i] != RSA_ENCRYPTION_OID[i]) {
                        rsaFlag = false;
                    }
                }
                if (rsaFlag) break;
            }
//#if ANDROID
            PrivateKey importedPrivateKey = 
                    KeyFactory.getInstance(rsaFlag ? "RSA" : "EC").generatePrivate(keySpec);
            coreCompatibilityCheck(keyEntry, importedPrivateKey);
//#else
            keyEntry.privateKey = KeyFactory.getInstance(rsaFlag ? "RSA" : "EC").generatePrivate(keySpec);
            coreCompatibilityCheck(keyEntry);
//#endif
            if (rsaFlag) {
                // https://stackoverflow.com/questions/24121801/how-to-verify-if-the-private-key-matches-with-the-certificate
                if (!(((RSAPublicKey)keyEntry.publicKey).getModulus()
                            .equals(((RSAPrivateKey)MACRO_IMPORTED_PRIVATEKEY).getModulus()) &&
                      BigInteger.valueOf(2).modPow(((RSAPublicKey)keyEntry.publicKey).getPublicExponent()
                                .multiply(((RSAPrivateKey)MACRO_IMPORTED_PRIVATEKEY).getPrivateExponent())
                                .subtract(BigInteger.ONE),((RSAPublicKey) keyEntry.publicKey).getModulus())
                            .equals(BigInteger.ONE))) {
                    abort("Imported RSA key does not match certificate for: " + keyEntry.id);
                }
            } else {
                checkEcKeyCompatibility((ECPrivateKey)MACRO_IMPORTED_PRIVATEKEY, keyEntry.id);
            }
//#if ANDROID
            HardwareKeyStore.importKey(keyEntry.getKeyId(), importedPrivateKey, keyEntry.certificatePath);
            logCertificateOperation(keyEntry, "private key import");
//#endif
        } catch (Exception e) {
            tearDownSession(keyEntry, e);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           importSymmetricKey                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void importSymmetricKey(int keyHandle,
                                                byte[] encryptedKey,
                                                byte[] mac) {
        KeyEntry keyEntry = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key and associated provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry = getOpenKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check for various input errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (encryptedKey.length > (MAX_LENGTH_SYMMETRIC_KEY + AES_CBC_PKCS5_PADDING)) {
                abort("Symmetric key: " + keyEntry.id + " exceeds " +
                                     MAX_LENGTH_SYMMETRIC_KEY + " bytes");
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Mark as "copied" by the server
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.setAndVerifyServerBackupFlag();
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = keyEntry.getEeCertMacBuilder(METHOD_IMPORT_SYMMETRIC_KEY);
            verifier.addArray(encryptedKey);
            keyEntry.owner.verifyMac(verifier, mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Decrypt and store symmetric key
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.symmetricKey = keyEntry.owner.decrypt(encryptedKey);
//#if ANDROID
            logCertificateOperation(keyEntry, "symmetric key import");
//#endif
        } catch (Exception e) {
            tearDownSession(keyEntry, e);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           setCertificatePath                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void setCertificatePath(int keyHandle,
                                                X509Certificate[] certificatePath,
                                                byte[] mac) {
        KeyEntry keyEntry = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key and associated provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry = getOpenKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = keyEntry.owner.getMacBuilderForMethodCall(METHOD_SET_CERTIFICATE_PATH);
            verifier.addArray(keyEntry.publicKey.getEncoded());
            verifier.addString(keyEntry.id);
            for (X509Certificate certificate : certificatePath) {
                byte[] der = certificate.getEncoded();
                if (der.length > MAX_LENGTH_CRYPTO_DATA) {
                    abort("Certificate for: " + keyEntry.id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
                }
                verifier.addArray(der);
            }
            keyEntry.owner.verifyMac(verifier, mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Update public key value.  It has no use after "setCertificatePath" anyway...
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.publicKey = certificatePath[0].getPublicKey();
            
            ///////////////////////////////////////////////////////////////////////////////////
            // Check key material for SKS compliance
            ///////////////////////////////////////////////////////////////////////////////////
            if (keyEntry.publicKey instanceof RSAKey) {
                checkRsaKeyCompatibility((RSAPublicKey) keyEntry.publicKey, keyEntry.id);
            } else if (keyEntry.publicKey instanceof ECKey) {
                checkEcKeyCompatibility((ECPublicKey) keyEntry.publicKey, keyEntry.id);
            }
//TODO X/ED

            ///////////////////////////////////////////////////////////////////////////////////
            // Store certificate path
            ///////////////////////////////////////////////////////////////////////////////////
            if (keyEntry.certificatePath != null) {
                abort("Multiple calls to \"setCertificatePath\" for: " + keyEntry.id);
            }
            keyEntry.certificatePath = certificatePath.clone();
//#if ANDROID
            logCertificateOperation(keyEntry, "received");
//#endif
        } catch (Exception e) {
            tearDownSession(keyEntry, e);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              createKeyEntry                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized KeyData createKeyEntry(int provisioningHandle,
                                               String id,
                                               String keyEntryAlgorithm,
                                               byte[] serverSeed,
                                               boolean devicePinProtection,
                                               int pinPolicyHandle,
                                               byte[] pinValue,
                                               boolean enablePinCaching,
                                               byte biometricProtection,
                                               byte exportProtection,
                                               byte deleteProtection,
                                               byte appUsage,
                                               String friendlyName,
                                               String keyAlgorithm,
                                               byte[] keyParameters,
                                               String[] endorsedAlgorithms,
                                               byte[] mac) {
        Provisioning provisioning = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning = getOpenProvisioningSession(provisioningHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Validate input as much as possible
            ///////////////////////////////////////////////////////////////////////////////////
            if (!keyEntryAlgorithm.equals(ALGORITHM_KEY_ATTEST_1)) {
                abort("Unknown \"" + VAR_KEY_ENTRY_ALGORITHM + "\" : " + keyEntryAlgorithm, SKSException.ERROR_ALGORITHM);
            }
            Algorithm kalg = supportedAlgorithms.get(keyAlgorithm);
            if (kalg == null || (kalg.mask & ALG_KEY_GEN) == 0) {
                abort("Unsupported \"" + VAR_KEY_ALGORITHM + "\": " + keyAlgorithm);
            }
            if ((kalg.mask & ALG_KEY_PARM) == 0 ^ keyParameters == null) {
                abort((keyParameters == null ? "Missing" : "Unexpected") + " \"" + VAR_KEY_PARAMETERS + "\"");
            }
            if (serverSeed == null) {
                serverSeed = ZERO_LENGTH_ARRAY;
            } else if (serverSeed.length > MAX_LENGTH_SERVER_SEED) {
                abort("\"" + VAR_SERVER_SEED + "\" length error: " + serverSeed.length);
            }
            provisioning.rangeTest(exportProtection, EXPORT_DELETE_PROTECTION_NONE, EXPORT_DELETE_PROTECTION_NOT_ALLOWED, VAR_EXPORT_PROTECTION);
            provisioning.rangeTest(deleteProtection, EXPORT_DELETE_PROTECTION_NONE, EXPORT_DELETE_PROTECTION_NOT_ALLOWED, VAR_DELETE_PROTECTION);
            provisioning.rangeTest(appUsage, APP_USAGE_SIGNATURE, APP_USAGE_UNIVERSAL, VAR_APP_USAGE);
            provisioning.rangeTest(biometricProtection, BIOMETRIC_PROTECTION_NONE, BIOMETRIC_PROTECTION_EXCLUSIVE, VAR_BIOMETRIC_PROTECTION);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Get proper PIN policy ID
            ///////////////////////////////////////////////////////////////////////////////////
            PINPolicy pinPolicy = null;
            boolean decryptPin = false;
            String pinPolicyId = CRYPTO_STRING_NOT_AVAILABLE;
            boolean pinProtection = true;
            if (devicePinProtection) {
                if (SKS_DEVICE_PIN_SUPPORT) {
                    if (pinPolicyHandle != 0) {
                        abort("Device PIN mixed with PIN policy ojbect");
                    }
                } else {
                    abort("Unsupported: \"" + VAR_DEVICE_PIN_PROTECTION + "\"");
                }
            } else if (pinPolicyHandle != 0) {
                pinPolicy = pinPolicies.get(pinPolicyHandle);
                if (pinPolicy == null || pinPolicy.owner != provisioning) {
                    abort("Referenced PIN policy object not found");
                }
                if (enablePinCaching && pinPolicy.inputMethod != INPUT_METHOD_TRUSTED_GUI) {
                    abort("\"" + VAR_ENABLE_PIN_CACHING + "\" must be combined with \"trusted-gui\"");
                }
                pinPolicyId = pinPolicy.id;
                provisioning.names.put(pinPolicyId, true); // Referenced
                decryptPin = !pinPolicy.userDefined;
            } else {
                verifyExportDeleteProtection(deleteProtection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
                verifyExportDeleteProtection(exportProtection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
                pinProtection = false;
                if (enablePinCaching) {
                    abort("\"" + VAR_ENABLE_PIN_CACHING + "\" without PIN");
                }
                if (pinValue != null) {
                    abort("\"" + VAR_PIN_VALUE + "\" expected to be empty");
                }
            }
            if (biometricProtection != BIOMETRIC_PROTECTION_NONE &&
                    ((biometricProtection != BIOMETRIC_PROTECTION_EXCLUSIVE) ^ pinProtection)) {
                abort("Invalid \"" + VAR_BIOMETRIC_PROTECTION + "\" and PIN combination");
            }
            if (pinPolicy == null || pinPolicy.pukPolicy == null) {
                verifyExportDeleteProtection(deleteProtection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
                verifyExportDeleteProtection(exportProtection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = provisioning.getMacBuilderForMethodCall(METHOD_CREATE_KEY_ENTRY);
            verifier.addString(id);
            verifier.addString(keyEntryAlgorithm);
            verifier.addArray(serverSeed);
            verifier.addString(pinPolicyId);
            if (decryptPin) {
                verifier.addArray(pinValue);
                pinValue = provisioning.decrypt(pinValue);
            } else {
                if (pinValue != null) {
                    pinValue = pinValue.clone();
                }
                verifier.addString(CRYPTO_STRING_NOT_AVAILABLE);
            }
            verifier.addBool(devicePinProtection);
            verifier.addBool(enablePinCaching);
            verifier.addByte(biometricProtection);
            verifier.addByte(exportProtection);
            verifier.addByte(deleteProtection);
            verifier.addByte(appUsage);
            verifier.addString(friendlyName == null ? "" : friendlyName);
            verifier.addString(keyAlgorithm);
            verifier.addArray(keyParameters == null ? ZERO_LENGTH_ARRAY : keyParameters);
            LinkedHashSet<String> tempEndorsed = new LinkedHashSet<>();
            String prevAlg = "\0";
            for (String endorsedAlgorithm : endorsedAlgorithms) {
                ///////////////////////////////////////////////////////////////////////////////////
                // Check that the algorithms are sorted and known
                ///////////////////////////////////////////////////////////////////////////////////
                if (prevAlg.compareTo(endorsedAlgorithm) >= 0) {
                    abort("Duplicate or incorrectly sorted algorithm: " + endorsedAlgorithm);
                }
                Algorithm alg = supportedAlgorithms.get(endorsedAlgorithm);
                if (alg == null || alg.mask == 0) {
                    abort("Unsupported algorithm: " + endorsedAlgorithm);
                }
                if ((alg.mask & ALG_NONE) != 0 && endorsedAlgorithms.length > 1) {
                    abort("Algorithm must be alone: " + endorsedAlgorithm);
                }
                tempEndorsed.add(prevAlg = endorsedAlgorithm);
                verifier.addString(endorsedAlgorithm);
            }
            provisioning.verifyMac(verifier, mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Perform a gazillion tests on PINs if applicable
            ///////////////////////////////////////////////////////////////////////////////////
            if (pinPolicy != null) {
                ///////////////////////////////////////////////////////////////////////////////////
                // Testing the actual PIN value
                ///////////////////////////////////////////////////////////////////////////////////
                verifyPinPolicyCompliance(false, pinValue, pinPolicy, appUsage);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Decode key algorithm specifier
            ///////////////////////////////////////////////////////////////////////////////////
            AlgorithmParameterSpec algParSpec = null;
            String keyFactory;
            if ((kalg.mask & ALG_RSA_KEY) == ALG_RSA_KEY) {
                keyFactory = "RSA";
                int rsaKeySize = kalg.mask & ALG_RSA_GMSK;
                BigInteger exponent = RSAKeyGenParameterSpec.F4;
                if (keyParameters != null) {
                    if (keyParameters.length == 0 || keyParameters.length > 8) {
                        abort("\"" + VAR_KEY_PARAMETERS + "\" length error: " + keyParameters.length);
                    }
                    exponent = new BigInteger(keyParameters);
                }
                algParSpec = new RSAKeyGenParameterSpec(rsaKeySize, exponent);
            } else if ((kalg.mask & ALG_EC_KEY) == ALG_EC_KEY) {
                keyFactory = "EC";
                algParSpec = new ECGenParameterSpec(kalg.jceName);
            } else {
//#if BOUNCYCASTLE
                keyFactory = null;
                abort("BC support for " + kalg.jceName + " not implemented");
//#else
//#if ANDROID
                keyFactory = "EC";
                algParSpec = new ECGenParameterSpec(kalg.jceName);
//#else
                keyFactory = ((kalg.mask & ALG_EDDSA_KEY) == ALG_EDDSA_KEY) ? "EdDSA" : "XDH";
                algParSpec = new NamedParameterSpec(kalg.jceName);
//#endif
//#endif
            }


            ///////////////////////////////////////////////////////////////////////////////////
            //Reserve a key entry
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = new KeyEntry(provisioning, id);
            provisioning.names.put(id, true); // Referenced (for "closeProvisioningSession")

            ///////////////////////////////////////////////////////////////////////////////////
            // Generate the desired key pair
            ///////////////////////////////////////////////////////////////////////////////////
//#if ANDROID
            PublicKey publicKey;
            if (exportProtection == EXPORT_DELETE_PROTECTION_NOT_ALLOWED) {
                publicKey = HardwareKeyStore.createSecureKeyPair(keyEntry.getKeyId(),
                                                         algParSpec,
                                                         keyFactory);
            } else {
                SecureRandom secureRandom = serverSeed.length == 0 ? 
                                                new SecureRandom() : new SecureRandom(serverSeed);
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyFactory);
                kpg.initialize(algParSpec, secureRandom);
                KeyPair keyPair = kpg.generateKeyPair();
                keyEntry.exportablePrivateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
            }
//#else
            SecureRandom secureRandom = serverSeed.length == 0 ?
                                            new SecureRandom() : new SecureRandom(serverSeed);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyFactory);
            kpg.initialize(algParSpec, secureRandom);
            KeyPair keyPair = kpg.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
//#endif

            ///////////////////////////////////////////////////////////////////////////////////
            // Create key attest
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder cka = provisioning.getMacBuilderForMethodCall(KDF_DEVICE_ATTESTATION);
            cka.addArray(publicKey.getEncoded());
            cka.addArray(mac);
            byte[] attestation = cka.getResult();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, fill in the key attributes
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.pinPolicy = pinPolicy;
            keyEntry.friendlyName = friendlyName;
            keyEntry.pinValue = pinValue;
            keyEntry.publicKey = publicKey;
//#if !ANDROID
            keyEntry.privateKey = privateKey;
//#endif
            keyEntry.appUsage = appUsage;
            keyEntry.devicePinProtection = devicePinProtection;
            keyEntry.enablePinCaching = enablePinCaching;
            keyEntry.biometricProtection = biometricProtection;
            keyEntry.exportProtection = exportProtection;
            keyEntry.deleteProtection = deleteProtection;
            keyEntry.endorsedAlgorithms = tempEndorsed;
//#if ANDROID
            Log.i(SKS_DEBUG, "Key with algorithm \"" + keyAlgorithm + "\" created");
//#endif
            return new KeyData(keyEntry.keyHandle, publicKey, attestation);
        } catch (Exception e) {
            tearDownSession(provisioning, e);
            return null;    // For the compiler...
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            createPinPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized int createPinPolicy(int provisioningHandle,
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
                                            byte[] mac) {
        Provisioning provisioning = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning = getOpenProvisioningSession(provisioningHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Perform PIN "sanity" checks
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.rangeTest(grouping, PIN_GROUPING_NONE, PIN_GROUPING_UNIQUE, VAR_GROUPING);
            provisioning.rangeTest(inputMethod, INPUT_METHOD_ANY, INPUT_METHOD_TRUSTED_GUI, VAR_INPUT_METHOD);
            provisioning.passphraseFormatTest(format);
            provisioning.retryLimitTest(retryLimit, (short) 1);
            if ((patternRestrictions & ~(PIN_PATTERN_TWO_IN_A_ROW |
                                         PIN_PATTERN_THREE_IN_A_ROW |
                                         PIN_PATTERN_SEQUENCE |
                                         PIN_PATTERN_REPEATED |
                                         PIN_PATTERN_MISSING_GROUP)) != 0) {
                abort("Invalid \"" + VAR_PATTERN_RESTRICTIONS + "\" value=" + patternRestrictions);
            }
            String pukPolicyId = CRYPTO_STRING_NOT_AVAILABLE;
            PUKPolicy pukPolicy = null;
            if (pukPolicyHandle != 0) {
                pukPolicy = pukPolicies.get(pukPolicyHandle);
                if (pukPolicy == null || pukPolicy.owner != provisioning) {
                    abort("Referenced PUK policy object not found");
                }
                pukPolicyId = pukPolicy.id;
                provisioning.names.put(pukPolicyId, true); // Referenced
            }
            if ((patternRestrictions & PIN_PATTERN_MISSING_GROUP) != 0 &&
                    format != PASSPHRASE_FORMAT_ALPHANUMERIC && format != PASSPHRASE_FORMAT_STRING) {
                abort("Incorrect \"" + VAR_FORMAT + "\" for the \"missing-group\" PIN pattern policy");
            }
            if (minLength < 1 || maxLength > MAX_LENGTH_PIN_PUK || maxLength < minLength) {
                abort("PIN policy length error");
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = provisioning.getMacBuilderForMethodCall(METHOD_CREATE_PIN_POLICY);
            verifier.addString(id);
            verifier.addString(pukPolicyId);
            verifier.addBool(userDefined);
            verifier.addBool(userModifiable);
            verifier.addByte(format);
            verifier.addShort(retryLimit);
            verifier.addByte(grouping);
            verifier.addByte(patternRestrictions);
            verifier.addShort(minLength);
            verifier.addShort(maxLength);
            verifier.addByte(inputMethod);
            provisioning.verifyMac(verifier, mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, create object
            ///////////////////////////////////////////////////////////////////////////////////
            PINPolicy pinPolicy = new PINPolicy(provisioning, id);
            pinPolicy.pukPolicy = pukPolicy;
            pinPolicy.userDefined = userDefined;
            pinPolicy.userModifiable = userModifiable;
            pinPolicy.format = format;
            pinPolicy.retryLimit = retryLimit;
            pinPolicy.grouping = grouping;
            pinPolicy.patternRestrictions = patternRestrictions;
            pinPolicy.minLength = minLength;
            pinPolicy.maxLength = maxLength;
            pinPolicy.inputMethod = inputMethod;
//#if ANDROID
            Log.i(SKS_DEBUG, "PIN policy object created");
//#endif
            return pinPolicy.pinPolicyHandle;
        } catch (Exception e){
            tearDownSession(provisioning, e);
            return 0;  // For the compiler...
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            createPukPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized int createPukPolicy(int provisioningHandle,
                                            String id,
                                            byte[] pukValue,
                                            byte format,
                                            short retryLimit,
                                            byte[] mac) {
        Provisioning provisioning = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning = getOpenProvisioningSession(provisioningHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Perform PUK "sanity" checks
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.passphraseFormatTest(format);
            provisioning.retryLimitTest(retryLimit, (short) 0);
            byte[] decryptedPukValue = provisioning.decrypt(pukValue);
            if (decryptedPukValue.length == 0 || decryptedPukValue.length > MAX_LENGTH_PIN_PUK) {
                abort("PUK length error");
            }
            for (int i = 0; i < decryptedPukValue.length; i++) {
                byte c = decryptedPukValue[i];
                if ((c < '0' || c > '9') && (format == PASSPHRASE_FORMAT_NUMERIC ||
                        ((c < 'A' || c > 'Z') && format == PASSPHRASE_FORMAT_ALPHANUMERIC))) {
                    abort("PUK syntax error");
                }
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = provisioning.getMacBuilderForMethodCall(METHOD_CREATE_PUK_POLICY);
            verifier.addString(id);
            verifier.addArray(pukValue);
            verifier.addByte(format);
            verifier.addShort(retryLimit);
            provisioning.verifyMac(verifier, mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, create object
            ///////////////////////////////////////////////////////////////////////////////////
            PUKPolicy pukPolicy = new PUKPolicy(provisioning, id);
            pukPolicy.pukValue = decryptedPukValue;
            pukPolicy.format = format;
            pukPolicy.retryLimit = retryLimit;
//#if ANDROID
            Log.i(SKS_DEBUG, "PUK policy object created");
//#endif
            return pukPolicy.pukPolicyHandle;
        } catch (Exception e) {
            tearDownSession(provisioning, e);
            return 0;  // For the compiler...
        }
    }
//#if ANDROID

    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                      A set of public non-SKS methods                       //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////

    @Override
    public boolean isGranted(int keyHandle, String domain) {
        KeyEntry keyEntry = getStdKey(keyHandle);
        return keyEntry.grantedDomains.contains(domain);
    }

    @Override
    public void setGrant(int keyHandle, String domain, boolean granted) {
        KeyEntry keyEntry = getStdKey(keyHandle);
        if (granted) {
            keyEntry.grantedDomains.add(domain);
        } else {
            keyEntry.grantedDomains.remove(domain);
        }
    }

    @Override
    public String[] listGrants(int keyHandle) {
        KeyEntry keyEntry = getStdKey(keyHandle);
        return keyEntry.grantedDomains.toArray(new String[0]);
    }
//#endif
}
