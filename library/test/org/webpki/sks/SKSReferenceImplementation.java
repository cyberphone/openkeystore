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

import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
public class SKSReferenceImplementation implements SKSError, SecureKeyStore, Serializable {
    private static final long serialVersionUID = 1L;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS version and configuration data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final String SKS_VENDOR_NAME                    = "WebPKI.org";
    static final String SKS_VENDOR_DESCRIPTION             = "SKS Reference - Java Emulator Edition";
    static final String SKS_UPDATE_URL                     = null;  // Change here to test or disable
    static final boolean SKS_DEVICE_PIN_SUPPORT            = true;  // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT             = true;  // Change here to test or disable
    static final boolean SKS_RSA_EXPONENT_SUPPORT          = true;  // Change here to test or disable
    static final int MAX_LENGTH_CRYPTO_DATA                = 16384;
    static final int MAX_LENGTH_EXTENSION_DATA             = 65536;

    static final char[] BASE64_URL = {'A','B','C','D','E','F','G','H',
                                      'I','J','K','L','M','N','O','P',
                                      'Q','R','S','T','U','V','W','X',
                                      'Y','Z','a','b','c','d','e','f',
                                      'g','h','i','j','k','l','m','n',
                                      'o','p','q','r','s','t','u','v',
                                      'w','x','y','z','0','1','2','3',
                                      '4','5','6','7','8','9','-','_'};

    int nextKeyHandle = 1;
    LinkedHashMap<Integer, KeyEntry> keys = new LinkedHashMap<Integer, KeyEntry>();

    int nextProvHandle = 1;
    LinkedHashMap<Integer, Provisioning> provisionings = new LinkedHashMap<Integer, Provisioning>();

    int nextPinHandle = 1;
    LinkedHashMap<Integer, PINPolicy> pinPolicies = new LinkedHashMap<Integer, PINPolicy>();

    int nextPukHandle = 1;
    LinkedHashMap<Integer, PUKPolicy> pukPolicies = new LinkedHashMap<Integer, PUKPolicy>();


    abstract class NameSpace implements Serializable {
        private static final long serialVersionUID = 1L;

        String id;

        Provisioning owner;

        NameSpace(Provisioning owner, String id) throws SKSException {
            //////////////////////////////////////////////////////////////////////
            // Keys, PINs and PUKs share virtual ID space during provisioning
            //////////////////////////////////////////////////////////////////////
            if (owner.names.get(id) != null) {
                owner.abort("Duplicate \"" + VAR_ID + "\" : " + id);
            }
            checkIdSyntax(id, VAR_ID, owner);
            owner.names.put(id, false);
            this.owner = owner;
            this.id = id;
        }
    }


    static void checkIdSyntax(String identifier, String symbolicName, SKSError sksError) throws SKSException {
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
            sksError.abort("Malformed \"" + symbolicName + "\" : " + identifier);
        }
    }


    class KeyEntry extends NameSpace implements Serializable {
        private static final long serialVersionUID = 1L;

        int keyHandle;

        byte appUsage;

        PublicKey publicKey;     // In this implementation overwritten by "setCertificatePath"
        PrivateKey privateKey;   // Overwritten if "restorePivateKey" is called
        X509Certificate[] certificatePath;

        byte[] symmetricKey;     // Defined by "importSymmetricKey"

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


        LinkedHashMap<String, ExtObject> extensions = new LinkedHashMap<String, ExtObject>();

        KeyEntry(Provisioning owner, String id) throws SKSException {
            super(owner, id);
            keyHandle = nextKeyHandle++;
            keys.put(keyHandle, this);
        }

        void authError() throws SKSException {
            abort("\"" + VAR_AUTHORIZATION + "\" error for key #" + keyHandle, SKSException.ERROR_AUTHORIZATION);
        }

        @SuppressWarnings("fallthrough")
        Vector<KeyEntry> getPinSynchronizedKeys() {
            Vector<KeyEntry> group = new Vector<KeyEntry>();
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

        void verifyPin(byte[] pin) throws SKSException {
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

        void verifyPuk(byte[] puk) throws SKSException {
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

        void authorizeExportOrDeleteOperation(byte policy, byte[] authorization) throws SKSException {
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

        void checkEECertificateAvailability() throws SKSException {
            if (certificatePath == null) {
                owner.abort("Missing \"setCertificatePath\" for: " + id);
            }
        }

        MacBuilder getEeCertMacBuilder(byte[] method) throws SKSException {
            checkEECertificateAvailability();
            MacBuilder macBuilder = owner.getMacBuilderForMethodCall(method);
            try {
                macBuilder.addArray(certificatePath[0].getEncoded());
                return macBuilder;
            } catch (GeneralSecurityException e) {
                throw new SKSException(e, SKSException.ERROR_INTERNAL);
            }
        }

        void validateTargetKeyReference(MacBuilder verifier,
                                        byte[] mac,
                                        byte[] authorization,
                                        Provisioning provisioning) throws SKSException {
            ///////////////////////////////////////////////////////////////////////////////////
            // "Sanity check"
            ///////////////////////////////////////////////////////////////////////////////////
            if (provisioning.privacyEnabled ^ owner.privacyEnabled) {
                provisioning.abort("Inconsistent use of the \"" + VAR_PRIVACY_ENABLED + "\" attribute for key #" + keyHandle);
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify MAC
            ///////////////////////////////////////////////////////////////////////////////////
            verifier.addArray(authorization);
            provisioning.verifyMac(verifier, mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify KMK signature
            ///////////////////////////////////////////////////////////////////////////////////
            try {
                if (!owner.verifyKeyManagementKeyAuthorization(KMK_TARGET_KEY_REFERENCE,
                        provisioning.getMacBuilder(getDeviceID(provisioning.privacyEnabled))
                            .addVerbatim(certificatePath[0].getEncoded()).getResult(), authorization)) {
                    provisioning.abort("\"" + VAR_AUTHORIZATION + "\" signature did not verify for key #" + keyHandle);
                }
            } catch (GeneralSecurityException e) {
                provisioning.abort(e.getMessage(), SKSException.ERROR_CRYPTO);
            }
        }

        boolean isRsa() {
            return publicKey instanceof RSAPublicKey;
        }

        boolean isSymmetric() {
            return symmetricKey != null;
        }

        void checkCryptoDataSize(byte[] data) throws SKSException {
            if (data.length > MAX_LENGTH_CRYPTO_DATA) {
                abort("Exceeded \"" + VAR_CRYPTO_DATA_SIZE + "\" for key #" + keyHandle);
            }
        }

        void setAndVerifyServerBackupFlag() throws SKSException {
            if ((keyBackup & KeyProtectionInfo.KEYBACKUP_IMPORTED) != 0) {
                owner.abort("Mutiple key imports for: " + id);
            }
            keyBackup |= KeyProtectionInfo.KEYBACKUP_IMPORTED;
        }

        BigInteger getPublicRSAExponentFromPrivateKey() {
            return ((RSAPrivateCrtKey) privateKey).getPublicExponent();
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

        PINPolicy(Provisioning owner, String id) throws SKSException {
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

        PUKPolicy(Provisioning owner, String id) throws SKSException {
            super(owner, id);
            pukPolicyHandle = nextPukHandle++;
            pukPolicies.put(pukPolicyHandle, this);
        }
    }


    class Provisioning implements SKSError, Serializable {
        private static final long serialVersionUID = 1L;

        int provisioningHandle;

        // The virtual/shared name-space
        LinkedHashMap<String, Boolean> names = new LinkedHashMap<String, Boolean>();

        // Post provisioning management
        Vector<PostProvisioningObject> postProvisioningObjects = new Vector<PostProvisioningObject>();

        boolean privacyEnabled;
        String clientSessionId;
        String serverSessionId;
        String issuerUri;
        byte[] sessionKey;
        boolean open = true;
        PublicKey keyManagementKey;
        short macSequenceCounter;
        int clientTime;
        int sessionLifeTime;
        short sessionKeyLimit;

        Provisioning() {
            provisioningHandle = nextProvHandle++;
            provisionings.put(provisioningHandle, this);
        }

        void verifyMac(MacBuilder actualMac, byte[] claimedMac) throws SKSException {
            if (!Arrays.equals(actualMac.getResult(), claimedMac)) {
                abort("MAC error", SKSException.ERROR_MAC);
            }
        }

        void abort(String message, int exceptionType) throws SKSException {
            abortProvisioningSession(provisioningHandle);
            throw new SKSException(message, exceptionType);
        }

        @Override
        public void abort(String message) throws SKSException {
            abort(message, SKSException.ERROR_OPTION);
        }

        byte[] decrypt(byte[] data) throws SKSException {
            byte[] key = getMacBuilder(ZERO_LENGTH_ARRAY).addVerbatim(KDF_ENCRYPTION_KEY).getResult();
            try {
                Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                crypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(data, 0, 16));
                return crypt.doFinal(data, 16, data.length - 16);
            } catch (GeneralSecurityException e) {
                throw new SKSException(e);
            }
        }

        MacBuilder getMacBuilder(byte[] keyModifier) throws SKSException {
            if (sessionKeyLimit-- <= 0) {
                abort("\"" + VAR_SESSION_KEY_LIMIT + "\" exceeded");
            }
            try {
                return new MacBuilder(addArrays(sessionKey, keyModifier));
            } catch (GeneralSecurityException e) {
                throw new SKSException(e);
            }
        }

        MacBuilder getMacBuilderForMethodCall(byte[] method) throws SKSException {
            short q = macSequenceCounter++;
            return getMacBuilder(addArrays(method, new byte[]{(byte) (q >>> 8), (byte) q}));
        }

        KeyEntry getTargetKey(int keyHandle) throws SKSException {
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
                                       boolean updateOrDelete) throws SKSException {
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

        void rangeTest(byte value, byte lowLimit, byte highLimit, String objectName) throws SKSException {
            if (value > highLimit || value < lowLimit) {
                abort("Invalid \"" + objectName + "\" value=" + value);
            }
        }

        void passphraseFormatTest(byte format) throws SKSException {
            rangeTest(format, PASSPHRASE_FORMAT_NUMERIC, PASSPHRASE_FORMAT_BINARY, "Format");
        }

        void retryLimitTest(short retryLimit, short min) throws SKSException {
            if (retryLimit < min || retryLimit > MAX_RETRY_LIMIT) {
                abort("Invalid \"" + VAR_RETRY_LIMIT + "\" value=" + retryLimit);
            }
        }

        boolean verifyKeyManagementKeyAuthorization(byte[] kmkKdf,
                                                    byte[] argument,
                                                    byte[] authorization) throws GeneralSecurityException {
            return new SignatureWrapper(keyManagementKey instanceof RSAPublicKey ?
                                           "SHA256WithRSA" : "SHA256WithECDSA",
                                        keyManagementKey)
                .update(kmkKdf)
                .update(argument)
                .verify(authorization);
        }
    }


    class MacBuilder implements Serializable {
        private static final long serialVersionUID = 1L;

        Mac mac;

        MacBuilder(byte[] key) throws GeneralSecurityException {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "RAW"));
        }

        MacBuilder addVerbatim(byte[] data) {
            mac.update(data);
            return this;
        }

        void addArray(byte[] data) {
            addShort(data.length);
            mac.update(data);
        }

        void addBlob(byte[] data) {
            addInt(data.length);
            mac.update(data);
        }

        void addString(String string) throws SKSException {
            addArray(getBinary(string));
        }

        void addInt(int i) {
            mac.update((byte) (i >>> 24));
            mac.update((byte) (i >>> 16));
            mac.update((byte) (i >>> 8));
            mac.update((byte) i);
        }

        void addShort(int s) {
            mac.update((byte) (s >>> 8));
            mac.update((byte) s);
        }

        void addByte(byte b) {
            mac.update(b);
        }

        void addBool(boolean flag) {
            mac.update(flag ? (byte) 0x01 : (byte) 0x00);
        }

        byte[] getResult() {
            return mac.doFinal();
        }
    }


    class AttestationSignatureGenerator {

        SignatureWrapper signer;

        AttestationSignatureGenerator() throws GeneralSecurityException {
            PrivateKey attester = getAttestationKey();
            signer = new SignatureWrapper(attester instanceof RSAPrivateKey ? "SHA256withRSA" : "SHA256withECDSA",
                                          attester);
        }

        private byte[] short2bytes(int s) {
            return new byte[]{(byte) (s >>> 8), (byte) s};
        }

        private byte[] int2bytes(int i) {
            return new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
        }

        void addBlob(byte[] data) throws GeneralSecurityException {
            signer.update(int2bytes(data.length));
            signer.update(data);
        }

        void addArray(byte[] data) throws GeneralSecurityException {
            signer.update(short2bytes(data.length));
            signer.update(data);
        }

        void addString(String string) throws IOException, GeneralSecurityException {
            addArray(string.getBytes("UTF-8"));
        }

        void addInt(int i) throws GeneralSecurityException {
            signer.update(int2bytes(i));
        }

        void addShort(int s) throws GeneralSecurityException {
            signer.update(short2bytes(s));
        }

        void addByte(byte b) throws GeneralSecurityException {
            signer.update(b);
        }

        void addBool(boolean flag) throws GeneralSecurityException {
            signer.update(flag ? (byte) 0x01 : (byte) 0x00);
        }

        byte[] getResult() throws GeneralSecurityException, IOException {
            return signer.sign();
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
        boolean rsaFlag;
        int extendTo;

        public SignatureWrapper(String algorithm, PublicKey publicKey) throws GeneralSecurityException {
            instance = Signature.getInstance(algorithm);
            instance.initVerify(publicKey);
            rsaFlag = publicKey instanceof RSAPublicKey;
            if (!rsaFlag) {
                extendTo = getEcPointLength((ECKey) publicKey);
            }
        }

        public SignatureWrapper(String algorithm, PrivateKey privateKey) throws GeneralSecurityException {
            instance = Signature.getInstance(algorithm);
            instance.initSign(privateKey);
            rsaFlag = privateKey instanceof RSAPrivateKey;
            if (!rsaFlag) {
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
            if (rsaFlag) {
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
            if (rsaFlag) {
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
        byte[] pkcs1DigestInfo;
        ECParameterSpec ecParameterSpec;
        int ecPointLength;

        void addEcCurve(int ecPointLength, byte[] samplePublicKey) {
            this.ecPointLength = ecPointLength;
            try {
                ecParameterSpec = ((ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(samplePublicKey))).getParams();
            } catch (Exception e) {
                new RuntimeException(e);
            }
        }
    }

    static LinkedHashMap<String, Algorithm> supportedAlgorithms = new LinkedHashMap<String, Algorithm>();

    static Algorithm addAlgorithm(String uri, String jceName, int mask) {
        Algorithm alg = new Algorithm();
        alg.mask = mask;
        alg.jceName = jceName;
        supportedAlgorithms.put(uri, alg);
        return alg;
    }

    static final int ALG_SYM_ENC  = 0x00000001;
    static final int ALG_IV_REQ   = 0x00000002;
    static final int ALG_IV_INT   = 0x00000004;
    static final int ALG_SYML_128 = 0x00000008;
    static final int ALG_SYML_192 = 0x00000010;
    static final int ALG_SYML_256 = 0x00000020;
    static final int ALG_HMAC     = 0x00000040;
    static final int ALG_ASYM_ENC = 0x00000080;
    static final int ALG_ASYM_SGN = 0x00000100;
    static final int ALG_RSA_KEY  = 0x00004000;
    static final int ALG_RSA_GMSK = 0x00003FFF;
    static final int ALG_RSA_EXP  = 0x00008000;
    static final int ALG_HASH_256 = 0x00200000;
    static final int ALG_HASH_384 = 0x00300000;
    static final int ALG_HASH_512 = 0x00400000;
    static final int ALG_HASH_DIV = 0x00010000;
    static final int ALG_HASH_MSK = 0x0000007F;
    static final int ALG_NONE     = 0x00800000;
    static final int ALG_ASYM_KA  = 0x01000000;
    static final int ALG_AES_PAD  = 0x02000000;
    static final int ALG_EC_KEY   = 0x04000000;
    static final int ALG_KEY_GEN  = 0x08000000;
    static final int ALG_KEY_PARM = 0x10000000;

    static {
        //////////////////////////////////////////////////////////////////////////////////////
        //  Symmetric Key Encryption and Decryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_128);

        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_192);

        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_256);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#aes.ecb.nopad",
                     "AES/ECB/NoPadding",
                     ALG_SYM_ENC | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256 | ALG_AES_PAD);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#aes.cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_ENC | ALG_IV_REQ | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256);

        //////////////////////////////////////////////////////////////////////////////////////
        //  HMAC Operations
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1", "HmacSHA1", ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256", ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HmacSHA384", ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HmacSHA512", ALG_HMAC);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Decryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.es.pkcs1_5",
                     "RSA/ECB/PKCS1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha1.mgf1p",
                     "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha256.mgf1p",
                     "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.raw",
                     "RSA/ECB/NoPadding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Diffie-Hellman Key Agreement
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ecdh.raw",
                     "ECDH",
                     ALG_ASYM_KA | ALG_EC_KEY);
        
        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Signatures
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                     "NONEwithRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_256).pkcs1DigestInfo =
                         new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                     "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_384).pkcs1DigestInfo =
                          new byte[]{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                     0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
                     "NONEwithRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_512).pkcs1DigestInfo =
                         new byte[]{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                    0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_256);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_384);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_512);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.pkcs1.none",
                     "NONEwithRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ecdsa.none",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Generation
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ec.nist.p256",
                     "secp256r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve (32, new byte[]
              {(byte)0x30, (byte)0x59, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
               (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x08, (byte)0x2A,
               (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x03,
               (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x8B, (byte)0xDF, (byte)0x5D, (byte)0xA2, (byte)0xBE,
               (byte)0x57, (byte)0x73, (byte)0xAC, (byte)0x78, (byte)0x86, (byte)0xD3, (byte)0xE5, (byte)0xE6,
               (byte)0xC4, (byte)0xA5, (byte)0x6C, (byte)0x32, (byte)0xE2, (byte)0x28, (byte)0xBE, (byte)0xA0,
               (byte)0x0F, (byte)0x8F, (byte)0xBF, (byte)0x29, (byte)0x1E, (byte)0xC6, (byte)0x67, (byte)0xB3,
               (byte)0x51, (byte)0x99, (byte)0xB7, (byte)0xAD, (byte)0x13, (byte)0x0C, (byte)0x5A, (byte)0x7C,
               (byte)0x66, (byte)0x4B, (byte)0x47, (byte)0xF6, (byte)0x1F, (byte)0x41, (byte)0xE9, (byte)0xB3,
               (byte)0xB2, (byte)0x40, (byte)0xC0, (byte)0x65, (byte)0xF8, (byte)0x8F, (byte)0x30, (byte)0x0A,
               (byte)0xCA, (byte)0x5F, (byte)0xB5, (byte)0x09, (byte)0x6E, (byte)0x95, (byte)0xCF, (byte)0x78,
               (byte)0x7C, (byte)0x0D, (byte)0xB2});

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ec.nist.p384",
                     "secp384r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve (48, new byte[]
              {(byte)0x30, (byte)0x76, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
               (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05, (byte)0x2B,
               (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x22, (byte)0x03, (byte)0x62, (byte)0x00, (byte)0x04,
               (byte)0x63, (byte)0x5C, (byte)0x35, (byte)0x5C, (byte)0xC0, (byte)0xDF, (byte)0x90, (byte)0x16,
               (byte)0xA6, (byte)0x18, (byte)0xF1, (byte)0x50, (byte)0xA7, (byte)0x73, (byte)0xE7, (byte)0x05,
               (byte)0x22, (byte)0x36, (byte)0xF7, (byte)0xDC, (byte)0x9F, (byte)0xD8, (byte)0xA5, (byte)0xAC,
               (byte)0x71, (byte)0x9F, (byte)0x1C, (byte)0x9A, (byte)0x71, (byte)0x94, (byte)0x8B, (byte)0x81,
               (byte)0x15, (byte)0x32, (byte)0x24, (byte)0x92, (byte)0x11, (byte)0x11, (byte)0xDC, (byte)0x7E,
               (byte)0x9D, (byte)0x70, (byte)0x1A, (byte)0x9B, (byte)0x83, (byte)0x33, (byte)0x8B, (byte)0x59,
               (byte)0xC1, (byte)0x93, (byte)0x34, (byte)0x7F, (byte)0x58, (byte)0x0D, (byte)0x91, (byte)0xC4,
               (byte)0xD2, (byte)0x20, (byte)0x8F, (byte)0x64, (byte)0x16, (byte)0x16, (byte)0xEE, (byte)0x07,
               (byte)0x51, (byte)0xC3, (byte)0xF8, (byte)0x56, (byte)0x5B, (byte)0xCD, (byte)0x49, (byte)0xFE,
               (byte)0xE0, (byte)0xE2, (byte)0xD5, (byte)0xC5, (byte)0x79, (byte)0xD1, (byte)0xA6, (byte)0x18,
               (byte)0x82, (byte)0xBD, (byte)0x65, (byte)0x83, (byte)0xB6, (byte)0x84, (byte)0x77, (byte)0xE8,
               (byte)0x1F, (byte)0xB8, (byte)0xD7, (byte)0x3D, (byte)0x79, (byte)0x88, (byte)0x2E, (byte)0x98});

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ec.nist.p521",
                     "secp521r1",
                      ALG_EC_KEY | ALG_KEY_GEN).addEcCurve (66, new byte[]
              {(byte)0x30, (byte)0x81, (byte)0x9B, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2A,
               (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05,
               (byte)0x2B, (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x23, (byte)0x03, (byte)0x81, (byte)0x86,
               (byte)0x00, (byte)0x04, (byte)0x01, (byte)0xFC, (byte)0xA0, (byte)0x56, (byte)0x27, (byte)0xB7,
               (byte)0x68, (byte)0x25, (byte)0xC5, (byte)0x83, (byte)0xD1, (byte)0x34, (byte)0x0A, (byte)0xAE,
               (byte)0x96, (byte)0x1D, (byte)0xDC, (byte)0xE0, (byte)0x95, (byte)0xC5, (byte)0xE0, (byte)0x25,
               (byte)0x1F, (byte)0x46, (byte)0xF6, (byte)0x36, (byte)0xD7, (byte)0x3F, (byte)0xD9, (byte)0x5A,
               (byte)0x15, (byte)0xE3, (byte)0x05, (byte)0xBA, (byte)0x14, (byte)0x06, (byte)0x1B, (byte)0xEB,
               (byte)0xD4, (byte)0x88, (byte)0xFC, (byte)0x0D, (byte)0x87, (byte)0x02, (byte)0x15, (byte)0x4E,
               (byte)0x7E, (byte)0xC0, (byte)0x9F, (byte)0xF6, (byte)0x1C, (byte)0x80, (byte)0x2C, (byte)0xE6,
               (byte)0x0D, (byte)0xF5, (byte)0x0E, (byte)0x6C, (byte)0xD9, (byte)0x55, (byte)0xFA, (byte)0xBD,
               (byte)0x6B, (byte)0x55, (byte)0xA1, (byte)0x0E, (byte)0x00, (byte)0x55, (byte)0x12, (byte)0x35,
               (byte)0x8D, (byte)0xFC, (byte)0x0A, (byte)0x42, (byte)0xE5, (byte)0x78, (byte)0x09, (byte)0xD6,
               (byte)0xF6, (byte)0x0C, (byte)0xBE, (byte)0x15, (byte)0x0A, (byte)0x7D, (byte)0xC2, (byte)0x2E,
               (byte)0x98, (byte)0xA1, (byte)0xE1, (byte)0x6A, (byte)0xF1, (byte)0x1F, (byte)0xD2, (byte)0x9F,
               (byte)0x9A, (byte)0x81, (byte)0x65, (byte)0x51, (byte)0x8F, (byte)0x6E, (byte)0xF1, (byte)0x3B,
               (byte)0x95, (byte)0x6B, (byte)0xCE, (byte)0x51, (byte)0x09, (byte)0xFF, (byte)0x23, (byte)0xDC,
               (byte)0xE8, (byte)0x71, (byte)0x1A, (byte)0x94, (byte)0xC7, (byte)0x8E, (byte)0x4A, (byte)0xA9,
               (byte)0x22, (byte)0xA8, (byte)0x87, (byte)0x64, (byte)0xD0, (byte)0x36, (byte)0xAF, (byte)0xD3,
               (byte)0x69, (byte)0xAC, (byte)0xCA, (byte)0xCB, (byte)0x1A, (byte)0x96});

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ec.brainpool.p256r1",
                     "brainpoolP256r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve (32, new byte[]
              {(byte)0x30, (byte)0x5A, (byte)0x30, (byte)0x14, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
               (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x09, (byte)0x2B,
               (byte)0x24, (byte)0x03, (byte)0x03, (byte)0x02, (byte)0x08, (byte)0x01, (byte)0x01, (byte)0x07,
               (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x26, (byte)0x3C, (byte)0x91, (byte)0x3F,
               (byte)0x6B, (byte)0x91, (byte)0x10, (byte)0x6F, (byte)0xE4, (byte)0xA2, (byte)0x2D, (byte)0xA4,
               (byte)0xBB, (byte)0xAB, (byte)0xCE, (byte)0x9E, (byte)0x41, (byte)0x01, (byte)0x0B, (byte)0xB0,
               (byte)0xC3, (byte)0x84, (byte)0xEF, (byte)0x35, (byte)0x0D, (byte)0x66, (byte)0xEE, (byte)0x0C,
               (byte)0xEC, (byte)0x60, (byte)0xB6, (byte)0xF5, (byte)0x54, (byte)0x54, (byte)0x27, (byte)0x2A,
               (byte)0x1D, (byte)0x07, (byte)0x61, (byte)0xB0, (byte)0xC3, (byte)0x01, (byte)0xE8, (byte)0xCB,
               (byte)0x52, (byte)0xF5, (byte)0x03, (byte)0xC1, (byte)0x0C, (byte)0x3F, (byte)0xF0, (byte)0x97,
               (byte)0xCD, (byte)0xC9, (byte)0x45, (byte)0xF3, (byte)0x21, (byte)0xC5, (byte)0xCF, (byte)0x41,
               (byte)0x17, (byte)0xF3, (byte)0x3A, (byte)0xB4});

        for (short rsa_size : SKS_DEFAULT_RSA_SUPPORT) {
            addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa" + rsa_size,
                         null, ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            if (SKS_RSA_EXPONENT_SUPPORT) {
                addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa" + rsa_size + ".exp",
                             null, ALG_KEY_PARM | ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            }
        }

        //////////////////////////////////////////////////////////////////////////////////////
        //  Special Algorithms
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm(ALGORITHM_SESSION_ATTEST_1, null, 0);

        addAlgorithm(ALGORITHM_KEY_ATTEST_1, null, 0);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#none", null, ALG_NONE);

    }

    static final byte[] RSA_ENCRYPTION_OID = {(byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86, 
                                              (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D,
                                              (byte) 0x01, (byte) 0x01, (byte) 0x01};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Utility Functions
    /////////////////////////////////////////////////////////////////////////////////////////////

    static final char[] ATTESTATION_KEY_PASSWORD = {'t', 'e', 's', 't', 'i', 'n', 'g'};

    static final String ATTESTATION_KEY_ALIAS = "mykey";

    KeyStore getAttestationKeyStore() throws GeneralSecurityException {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(getClass().getResourceAsStream("attestationkeystore.jks"), ATTESTATION_KEY_PASSWORD);
            return ks;
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    X509Certificate[] getDeviceCertificatePath() throws GeneralSecurityException {
        return new X509Certificate[]{(X509Certificate) getAttestationKeyStore().getCertificate(ATTESTATION_KEY_ALIAS)};
    }

    byte[] getDeviceID(boolean privacyEnabled) throws GeneralSecurityException {
        return privacyEnabled ? KDF_ANONYMOUS : getDeviceCertificatePath()[0].getEncoded();
    }

    PrivateKey getAttestationKey() throws GeneralSecurityException {
        return (PrivateKey) getAttestationKeyStore().getKey(ATTESTATION_KEY_ALIAS, ATTESTATION_KEY_PASSWORD);
    }

    Provisioning getProvisioningSession(int provisioningHandle) throws SKSException {
        Provisioning provisioning = provisionings.get(provisioningHandle);
        if (provisioning == null) {
            abort("No such provisioning session: " + provisioningHandle, SKSException.ERROR_NO_SESSION);
        }
        return provisioning;
    }

    Provisioning getOpenProvisioningSession(int provisioningHandle) throws SKSException {
        Provisioning provisioning = getProvisioningSession(provisioningHandle);
        if (!provisioning.open) {
            abort("Session not open: " + provisioningHandle, SKSException.ERROR_NO_SESSION);
        }
        return provisioning;
    }

    Provisioning getClosedProvisioningSession(int provisioningHandle) throws SKSException {
        Provisioning provisioning = getProvisioningSession(provisioningHandle);
        if (provisioning.open) {
            abort("Session is open: " + provisioningHandle, SKSException.ERROR_NOT_ALLOWED);
        }
        return provisioning;
    }

    byte[] getBinary(String string) throws SKSException {
        try {
            return string.getBytes("UTF-8");
        } catch (IOException e) {
            abort("Internal UTF-8");
            return null;
        }
    }

    int getShort(byte[] buffer, int index) {
        return ((buffer[index++] << 8) & 0xFFFF) + (buffer[index] & 0xFF);
    }

    KeyEntry getOpenKey(int keyHandle) throws SKSException {
        KeyEntry keyEntry = keys.get(keyHandle);
        if (keyEntry == null) {
            abort("Key not found #" + keyHandle, SKSException.ERROR_NO_KEY);
        }
        if (!keyEntry.owner.open) {
            abort("Key #" + keyHandle + " not belonging to open session", SKSException.ERROR_NO_KEY);
        }
        return keyEntry;
    }

    KeyEntry getStdKey(int keyHandle) throws SKSException {
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

    @Override
    public void abort(String message) throws SKSException {
        abort(message, SKSException.ERROR_OPTION);
    }

    void abort(String message, int option) throws SKSException {
        throw new SKSException(message, option);
    }

    Algorithm getEcType(ECKey ecKey) {
        for (String uri : supportedAlgorithms.keySet()) {
            ECParameterSpec ecParameterSpec = supportedAlgorithms.get(uri).ecParameterSpec;
            if (ecParameterSpec != null &&
                    ecKey.getParams().getCurve().equals(ecParameterSpec.getCurve()) &&
                    ecKey.getParams().getGenerator().equals(ecParameterSpec.getGenerator())) {
                return supportedAlgorithms.get(uri);
            }
        }
        return null;
    }

    String checkEcKeyCompatibility(ECKey ecKey, SKSError sksError, String keyId) throws SKSException {
        Algorithm ecType = getEcType(ecKey);
        if (ecType != null) {
            return ecType.jceName;
        }
        sksError.abort("Unsupported EC key algorithm for: " + keyId);
        return null;
    }

    int getEcPointLength(ECKey ecKey) throws GeneralSecurityException {
        Algorithm ecType = getEcType(ecKey);
        if (ecType != null) {
            return ecType.ecPointLength;
        }
        throw new GeneralSecurityException("Unsupported EC curve");
    }

    void checkRsaKeyCompatibility(int rsaKeySize,
                                  BigInteger exponent, 
                                  SKSError sksError,
                                  String keyId) throws SKSException {
        if (!SKS_RSA_EXPONENT_SUPPORT && !exponent.equals(RSAKeyGenParameterSpec.F4)) {
            sksError.abort("Unsupported RSA exponent value for: " + keyId);
        }
        boolean found = false;
        for (short keySize : SKS_DEFAULT_RSA_SUPPORT) {
            if (keySize == rsaKeySize) {
                found = true;
                break;
            }
        }
        if (!found) {
            sksError.abort("Unsupported RSA key size " + rsaKeySize + " for: " + keyId);
        }
    }

    int getRSAKeySize(RSAKey rsaKey) {
        byte[] modblob = rsaKey.getModulus().toByteArray();
        return (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
    }

    @SuppressWarnings("fallthrough")
    void verifyPinPolicyCompliance(boolean forcedSetter,
                                   byte[] pinValue,
                                   PINPolicy pinPolicy,
                                   byte appUsage,
                                   SKSError sksError) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN length
        ///////////////////////////////////////////////////////////////////////////////////
        if (pinValue.length > pinPolicy.maxLength || pinValue.length < pinPolicy.minLength) {
            sksError.abort("PIN length error");
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
            sksError.abort("PIN syntax error");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check PIN patterns
        ///////////////////////////////////////////////////////////////////////////////////
        if ((pinPolicy.patternRestrictions & PIN_PATTERN_MISSING_GROUP) != 0) {
            if (!upperalpha || !number ||
                (pinPolicy.format == PASSPHRASE_FORMAT_STRING && (!loweralpha || !nonalphanum))) {
                sksError.abort("Missing character group in PIN");
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
                sksError.abort("PIN must not be a sequence");
            }
        }
        if ((pinPolicy.patternRestrictions & PIN_PATTERN_REPEATED) != 0) {
            for (int i = 0; i < pinValue.length; i++) {
                byte b = pinValue[i];
                for (int j = 0; j < pinValue.length; j++) {
                    if (j != i && b == pinValue[j]) {
                        sksError.abort("Repeated PIN character");
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
                        sksError.abort("PIN with " + max + " or more of same the character in a row");
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
                            sksError.abort("Grouping = \"shared\" requires identical PINs");
                        }
                        continue;

                    case PIN_GROUPING_UNIQUE:
                        if (equal ^ (appUsage == keyEntry.appUsage)) {
                            sksError.abort("Grouping = \"unique\" PIN error");
                        }
                        continue;

                    case PIN_GROUPING_SIGN_PLUS_STD:
                        if (((appUsage == APP_USAGE_SIGNATURE) ^ (keyEntry.appUsage == APP_USAGE_SIGNATURE)) ^ !equal) {
                            sksError.abort("Grouping = \"signature+standard\" PIN error");
                        }
                }
            }
        }
    }

    void testUpdatablePin(KeyEntry keyEntry, byte[] newPin) throws SKSException {
        if (!keyEntry.pinPolicy.userModifiable) {
            abort("PIN for key #" + keyEntry.keyHandle + " is not user modifiable", SKSException.ERROR_NOT_ALLOWED);
        }
        verifyPinPolicyCompliance(true, newPin, keyEntry.pinPolicy, keyEntry.appUsage, this);
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

    Algorithm checkKeyAndAlgorithm(KeyEntry keyEntry, String inputAlgorithm, int expectedType) throws SKSException {
        Algorithm alg = getAlgorithm(inputAlgorithm);
        if ((alg.mask & expectedType) == 0) {
            abort("Algorithm does not match operation: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
        }
        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) != 0) ^ keyEntry.isSymmetric()) {
            abort((keyEntry.isSymmetric() ? "S" : "As") + "ymmetric key #" + keyEntry.keyHandle + " is incompatible with: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
        }
        if (keyEntry.isSymmetric()) {
            testAESKey(inputAlgorithm, keyEntry.symmetricKey, "#" + keyEntry.keyHandle, this);
        } else if (keyEntry.isRsa() ^ (alg.mask & ALG_RSA_KEY) != 0) {
            abort((keyEntry.isRsa() ? "RSA" : "EC") + " key #" + keyEntry.keyHandle + " is incompatible with: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
        }
        if (keyEntry.endorsedAlgorithms.isEmpty() || keyEntry.endorsedAlgorithms.contains(inputAlgorithm)) {
            return alg;
        }
        abort("\"" + VAR_ENDORSED_ALGORITHMS + "\" for key #" + keyEntry.keyHandle + " does not include: " + inputAlgorithm, SKSException.ERROR_ALGORITHM);
        return null;    // For the compiler only...
    }

    byte[] addArrays(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    void testAESKey(String algorithm, byte[] symmetricKey, String keyId, SKSError sksError) throws SKSException {
        Algorithm alg = getAlgorithm(algorithm);
        if ((alg.mask & ALG_SYM_ENC) != 0) {
            int l = symmetricKey.length;
            if (l == 16) l = ALG_SYML_128;
            else if (l == 24) l = ALG_SYML_192;
            else if (l == 32) l = ALG_SYML_256;
            else l = 0;
            if ((l & alg.mask) == 0) {
                sksError.abort("Key " + keyId + " has wrong size (" + symmetricKey.length + ") for algorithm: " + algorithm);
            }
        }
    }

    Algorithm getAlgorithm(String algorithmUri) throws SKSException {
        Algorithm alg = supportedAlgorithms.get(algorithmUri);
        if (alg == null) {
            abort("Unsupported algorithm: " + algorithmUri, SKSException.ERROR_ALGORITHM);
        }
        return alg;
    }

    void verifyExportDeleteProtection(byte actualProtection, byte minProtectionVal, Provisioning provisioning) throws SKSException {
        if (actualProtection >= minProtectionVal && actualProtection <= EXPORT_DELETE_PROTECTION_PUK) {
            provisioning.abort("Protection object lacks a PIN or PUK object");
        }
    }

    void addUpdateKeyOrCloneKeyProtection(int keyHandle,
                                          int targetKeyHandle,
                                          byte[] authorization,
                                          byte[] mac,
                                          boolean update) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get open key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry newKey = getOpenKey(keyHandle);
        Provisioning provisioning = newKey.owner;

        ///////////////////////////////////////////////////////////////////////////////////
        // Get key to be updated/cloned
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry targetKeyEntry = provisioning.getTargetKey(targetKeyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform some "sanity" tests
        ///////////////////////////////////////////////////////////////////////////////////
        if (newKey.pinPolicy != null || newKey.devicePinProtection) {
            provisioning.abort("Updated/cloned keys must not define PIN protection");
        }
        if (update) {
            if (targetKeyEntry.appUsage != newKey.appUsage) {
                provisioning.abort("Updated keys must have the same \"" + VAR_APP_USAGE + "\" as the target key");
            }
        } else {
            ///////////////////////////////////////////////////////////////////////////////////
            // Cloned keys must share the PIN of its parent
            ///////////////////////////////////////////////////////////////////////////////////
            if (targetKeyEntry.pinPolicy != null && targetKeyEntry.pinPolicy.grouping != PIN_GROUPING_SHARED) {
                provisioning.abort("A cloned key protection must have PIN grouping=\"shared\"");
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
    }

    void addUnlockKeyOrDeleteKey(int provisioningHandle,
                                 int targetKeyHandle,
                                 byte[] authorization,
                                 byte[] mac,
                                 boolean delete) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession(provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Get key to be deleted or unlocked
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry targetKeyEntry = provisioning.getTargetKey(targetKeyHandle);
        if (!delete && targetKeyEntry.pinPolicy == null) {
            provisioning.abort("Key #" + targetKeyHandle + " is not PIN protected");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC and target key data
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall(delete ? METHOD_POST_DELETE_KEY : METHOD_POST_UNLOCK_KEY);
        targetKeyEntry.validateTargetKeyReference(verifier, mac, authorization, provisioning);

        ///////////////////////////////////////////////////////////////////////////////////
        // Put the operation in the post-op buffer used by "closeProvisioningSession"
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.addPostProvisioningObject(targetKeyEntry, null, delete);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               unlockKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void unlockKey(int keyHandle, byte[] authorization) throws SKSException {
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
                                       byte[] newPin) throws SKSException {
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
                                    byte[] newPin) throws SKSException {
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
    public synchronized void deleteKey(int keyHandle, byte[] authorization) throws SKSException {
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
        localDeleteKey(keyEntry);
        deleteEmptySession(keyEntry.owner);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               exportKey                                    //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] exportKey(int keyHandle, byte[] authorization) throws SKSException {
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
        return keyEntry.isSymmetric() ? keyEntry.symmetricKey : keyEntry.privateKey.getEncoded();
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
                                         String value) throws SKSException {
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
                extObj.extensionData = addArrays(addArrays(Arrays.copyOfRange(extObj.extensionData, 0, ++i),
                        addArrays(new byte[]{(byte) (binValue.length >> 8), (byte) binValue.length}, binValue)),
                        Arrays.copyOfRange(extObj.extensionData, i + valueLen + 2, extObj.extensionData.length));
                return;
            }
            i += valueLen + 3;
        }
        abort("\"" + VAR_PROPERTY + "\" not found: " + name);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getExtension                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized Extension getExtension(int keyHandle, String type) throws SKSException {
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
                                                    byte[] authorization,
                                                    byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPin(authorization);

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
            cipher.init(Cipher.DECRYPT_MODE, keyEntry.privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             signHashedData                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] signHashedData(int keyHandle,
                                              String algorithm,
                                              byte[] parameters,
                                              byte[] authorization,
                                              byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPin(authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Enforce the data limit
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.checkCryptoDataSize(data);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the signature algorithm is known and applicable
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(keyEntry, algorithm, ALG_ASYM_SGN);
        int hashLen = (alg.mask / ALG_HASH_DIV) & ALG_HASH_MSK;
        if (hashLen > 0 && hashLen != data.length) {
            abort("Incorrect length of \"" + VAR_DATA + "\": " + data.length);
        }
        if (parameters != null)  // Only supports non-parameterized operations yet...
        {
            abort("\"" + VAR_PARAMETERS + "\" for key #" + keyHandle + " do not match algorithm");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            if (keyEntry.isRsa() && hashLen > 0) {
                data = addArrays(alg.pkcs1DigestInfo, data);
            }
            return new SignatureWrapper(alg.jceName, keyEntry.privateKey)
                .update(data)
                .sign();
        } catch (Exception e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
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
                                            byte[] authorization,
                                            ECPublicKey publicKey) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPin(authorization);

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
        checkEcKeyCompatibility(publicKey, this, "\"" + VAR_PUBLIC_KEY + "\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            KeyAgreement key_agreement = KeyAgreement.getInstance(alg.jceName);
            key_agreement.init(keyEntry.privateKey);
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
                                                   byte[] authorization,
                                                   byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPin(authorization);

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
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
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
                                           byte[] authorization,
                                           byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPin(authorization);

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
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getDeviceInfo                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized DeviceInfo getDeviceInfo() throws SKSException {
        try {
            return new DeviceInfo(SKS_API_LEVEL,
                                  (byte) (DeviceInfo.LOCATION_EMBEDDED | DeviceInfo.TYPE_SOFTWARE),
                                  SKS_UPDATE_URL,
                                  SKS_VENDOR_NAME,
                                  SKS_VENDOR_DESCRIPTION,
                                  getDeviceCertificatePath(),
                                  supportedAlgorithms.keySet().toArray(new String[0]),
                                  MAX_LENGTH_CRYPTO_DATA,
                                  MAX_LENGTH_EXTENSION_DATA,
                                  SKS_DEVICE_PIN_SUPPORT,
                                  SKS_BIOMETRIC_SUPPORT);
        } catch (GeneralSecurityException e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                             updateFirmware                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public String updateFirmware(byte[] chunk) throws SKSException {
        throw new SKSException("Updates are not supported", SKSException.ERROR_NOT_ALLOWED);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              enumerateKeys                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized EnumeratedKey enumerateKeys(int keyHandle) throws SKSException {
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
    public synchronized KeyProtectionInfo getKeyProtectionInfo(int keyHandle) throws SKSException {
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
    public synchronized KeyAttributes getKeyAttributes(int keyHandle) throws SKSException {
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
                                       byte[] authorization) throws SKSException {
        Provisioning provisioning = getClosedProvisioningSession(provisioningHandle);
        if (provisioning.keyManagementKey == null) {
            abort("Session is not updatable: " + provisioningHandle, SKSException.ERROR_NOT_ALLOWED);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify KMK signature
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            if (!provisioning.verifyKeyManagementKeyAuthorization(KMK_ROLL_OVER_AUTHORIZATION,
                                                                  keyManagementKey.getEncoded(),
                                                                  authorization)) {
                abort("\"" + VAR_AUTHORIZATION + "\" signature did not verify for session: " + provisioningHandle);
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Success, update KeyManagementKey
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.keyManagementKey = keyManagementKey;
        } catch (Exception e) {
            abort(e.getMessage(), SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       enumerateProvisioningSessions                        //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized EnumeratedProvisioningSession enumerateProvisioningSessions(int provisioningHandle,
                                                                                    boolean provisioningState) throws SKSException {
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
    //                      signProvisioningSessionData                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] signProvisioningSessionData(int provisioningHandle, byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession(provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Sign (HMAC) data using a derived SessionKey
        ///////////////////////////////////////////////////////////////////////////////////
        return provisioning.getMacBuilder(KDF_EXTERNAL_SIGNATURE).addVerbatim(data).getResult();
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getKeyHandle                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized int getKeyHandle(int provisioningHandle, String id) throws SKSException {
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
        provisioning.abort("Key " + id + " missing");
        return 0;    // For the compiler only...
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
                                           byte[] mac) throws SKSException {
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
                                           byte[] mac) throws SKSException {
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
                                                    byte[] mac) throws SKSException {
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
                                           byte[] mac) throws SKSException {
        addUpdateKeyOrCloneKeyProtection(keyHandle, targetKeyHandle, authorization, mac, true);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         abortProvisioningSession                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void abortProvisioningSession(int provisioningHandle) throws SKSException {
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
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        closeProvisioningSession                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] closeProvisioningSession(int provisioningHandle,
                                                        byte[] nonce,
                                                        byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession(provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = provisioning.getMacBuilderForMethodCall(METHOD_CLOSE_PROVISIONING_SESSION);
        verifier.addString(provisioning.clientSessionId);
        verifier.addString(provisioning.serverSessionId);
        verifier.addString(provisioning.issuerUri);
        verifier.addArray(nonce);
        provisioning.verifyMac(verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate the attestation in advance => checking SessionKeyLimit before "commit"
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder close_attestation = provisioning.getMacBuilderForMethodCall(KDF_DEVICE_ATTESTATION);
        close_attestation.addArray(nonce);
        byte[] attestation = close_attestation.getResult();

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform "sanity" checks on provisioned data
        ///////////////////////////////////////////////////////////////////////////////////
        for (String id : provisioning.names.keySet()) {
            if (!provisioning.names.get(id)) {
                provisioning.abort("Unreferenced object \"" + VAR_ID + "\" : " + id);
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
                if (keyEntry.isRsa() ^ keyEntry.privateKey instanceof RSAPrivateKey) {
                    provisioning.abort("RSA/EC mixup between public and private keys for: " + keyEntry.id);
                }
                if (keyEntry.isRsa()) {
                    if (!((RSAPublicKey) keyEntry.publicKey).getPublicExponent().equals(keyEntry.getPublicRSAExponentFromPrivateKey()) ||
                            !((RSAPublicKey) keyEntry.publicKey).getModulus().equals(((RSAPrivateKey) keyEntry.privateKey).getModulus())) {
                        provisioning.abort("RSA mismatch between public and private keys for: " + keyEntry.id);
                    }
                } else {
                    try {
                        Signature ecSigner = Signature.getInstance("SHA256withECDSA");
                        ecSigner.initSign(keyEntry.privateKey);
                        ecSigner.update(RSA_ENCRYPTION_OID);  // Any data could be used...
                        byte[] ecSignData = ecSigner.sign();
                        Signature ecVerifier = Signature.getInstance("SHA256withECDSA");
                        ecVerifier.initVerify(keyEntry.publicKey);
                        ecVerifier.update(RSA_ENCRYPTION_OID);
                        if (!ecVerifier.verify(ecSignData)) {
                            provisioning.abort("EC mismatch between public and private keys for: " + keyEntry.id);
                        }
                    } catch (GeneralSecurityException e) {
                        provisioning.abort(e.getMessage());
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
                            provisioning.abort("Duplicate certificate in \"setCertificatePath\" for: " + keyEntry.id);
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
                        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) == 0) ^ keyEntry.isSymmetric()) {
                            if (keyEntry.isSymmetric()) {
                                ///////////////////////////////////////////////////////////////////////////////////
                                // Symmetric. AES algorithms only operates on 128, 192, and 256 bit keys
                                ///////////////////////////////////////////////////////////////////////////////////
                                testAESKey(algorithm, keyEntry.symmetricKey, keyEntry.id, provisioning);
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
                        provisioning.abort((keyEntry.isSymmetric() ? "Symmetric" : keyEntry.isRsa() ? "RSA" : "EC") +
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
        return attestation;
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
                                                                      int sessionLifeTime,
                                                                      short sessionKeyLimit) throws SKSException {
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
        String jceName = checkEcKeyCompatibility(serverEphemeralKey, this, "\"" + VAR_SERVER_EPHEMERAL_KEY + "\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Check optional key management key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (keyManagementKey != null) {
            if (keyManagementKey instanceof RSAPublicKey) {
                checkRsaKeyCompatibility(getRSAKeySize((RSAPublicKey) keyManagementKey),
                        ((RSAPublicKey) keyManagementKey).getPublicExponent(), this, "\"" + VAR_KEY_MANAGEMENT_KEY + "\"");
            } else {
                checkEcKeyCompatibility((ECPublicKey) keyManagementKey, this, "\"" + VAR_KEY_MANAGEMENT_KEY + "\"");
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ServerSessionID
        ///////////////////////////////////////////////////////////////////////////////////
        checkIdSyntax(serverSessionId, VAR_SERVER_SESSION_ID, this);

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
            if (privacyEnabled) {
                ///////////////////////////////////////////////////////////////////////////////////
                // SessionKey attest
                ///////////////////////////////////////////////////////////////////////////////////
                MacBuilder ska = new MacBuilder(sessionKey);
                ska.addString(clientSessionId);
                ska.addString(serverSessionId);
                ska.addString(issuerUri);
                ska.addArray(getDeviceID(privacyEnabled));
                ska.addString(sessionKeyAlgorithm);
                ska.addBool(privacyEnabled);
                ska.addArray(serverEphemeralKey.getEncoded());
                ska.addArray(clientEphemeralKey.getEncoded());
                ska.addArray(keyManagementKey == null ? ZERO_LENGTH_ARRAY : keyManagementKey.getEncoded());
                ska.addInt(clientTime);
                ska.addInt(sessionLifeTime);
                ska.addShort(sessionKeyLimit);
                attestation = ska.getResult();
            } else {
                ///////////////////////////////////////////////////////////////////////////////////
                // Device private key attest
                ///////////////////////////////////////////////////////////////////////////////////
                AttestationSignatureGenerator pka = new AttestationSignatureGenerator();
                pka.addString(clientSessionId);
                pka.addString(serverSessionId);
                pka.addString(issuerUri);
                pka.addArray(getDeviceID(privacyEnabled));
                pka.addString(sessionKeyAlgorithm);
                pka.addBool(privacyEnabled);
                pka.addArray(serverEphemeralKey.getEncoded());
                pka.addArray(clientEphemeralKey.getEncoded());
                pka.addArray(keyManagementKey == null ? ZERO_LENGTH_ARRAY : keyManagementKey.getEncoded());
                pka.addInt(clientTime);
                pka.addInt(sessionLifeTime);
                pka.addShort(sessionKeyLimit);
                attestation = pka.getResult();
            }
        } catch (Exception e) {
            throw new SKSException(e);
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
                                          byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getOpenKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for duplicates and length errors
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.owner.rangeTest(subType, SUB_TYPE_EXTENSION, SUB_TYPE_LOGOTYPE, VAR_SUB_TYPE);
        if (type.length() == 0 || type.length() > MAX_LENGTH_URI) {
            keyEntry.owner.abort("URI length error: " + type.length());
        }
        if (keyEntry.extensions.get(type) != null) {
            keyEntry.owner.abort("Duplicate \"" + VAR_TYPE + "\" : " + type);
        }
        if (extensionData.length > (subType == SUB_TYPE_ENCRYPTED_EXTENSION ?
                MAX_LENGTH_EXTENSION_DATA + AES_CBC_PKCS5_PADDING : MAX_LENGTH_EXTENSION_DATA)) {
            keyEntry.owner.abort("Extension data exceeds " + MAX_LENGTH_EXTENSION_DATA + " bytes");
        }
        byte[] binQualifier = getBinary(qualifier);
        if (((subType == SUB_TYPE_LOGOTYPE) ^ (binQualifier.length != 0)) || binQualifier.length > MAX_LENGTH_QUALIFIER) {
            keyEntry.owner.abort("\"" + VAR_QUALIFIER + "\" length error");
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
                    keyEntry.owner.abort("\"" + VAR_PROPERTY_BAG + "\" format error: " + type);
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
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            importPrivateKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void importPrivateKey(int keyHandle,
                                              byte[] encryptedKey,
                                              byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getOpenKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for key length errors
        ///////////////////////////////////////////////////////////////////////////////////
        if (encryptedKey.length > (MAX_LENGTH_CRYPTO_DATA + AES_CBC_PKCS5_PADDING)) {
            keyEntry.owner.abort("Private key: " + keyEntry.id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
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
        try {
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
            keyEntry.privateKey = KeyFactory.getInstance(rsaFlag ? "RSA" : "EC").generatePrivate(keySpec);
            if (rsaFlag) {
                checkRsaKeyCompatibility(getRSAKeySize((RSAPrivateKey) keyEntry.privateKey),
                                         keyEntry.getPublicRSAExponentFromPrivateKey(),
                                         keyEntry.owner, keyEntry.id);
            } else {
                checkEcKeyCompatibility((ECPrivateKey) keyEntry.privateKey, keyEntry.owner, keyEntry.id);
            }
        } catch (GeneralSecurityException e) {
            keyEntry.owner.abort(e.getMessage(), SKSException.ERROR_CRYPTO);
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
                                                byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getOpenKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check for various input errors
        ///////////////////////////////////////////////////////////////////////////////////
        if (encryptedKey.length > (MAX_LENGTH_SYMMETRIC_KEY + AES_CBC_PKCS5_PADDING)) {
            keyEntry.owner.abort("Symmetric key: " + keyEntry.id + " exceeds " + MAX_LENGTH_SYMMETRIC_KEY + " bytes");
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
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           setCertificatePath                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized void setCertificatePath(int keyHandle,
                                                X509Certificate[] certificatePath,
                                                byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key and associated provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getOpenKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = keyEntry.owner.getMacBuilderForMethodCall(METHOD_SET_CERTIFICATE_PATH);
        try {
            verifier.addArray(keyEntry.publicKey.getEncoded());
            verifier.addString(keyEntry.id);
            for (X509Certificate certificate : certificatePath) {
                byte[] der = certificate.getEncoded();
                if (der.length > MAX_LENGTH_CRYPTO_DATA) {
                    keyEntry.owner.abort("Certificate for: " + keyEntry.id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
                }
                verifier.addArray(der);
            }
        } catch (GeneralSecurityException e) {
            keyEntry.owner.abort(e.getMessage(), SKSException.ERROR_INTERNAL);
        }
        keyEntry.owner.verifyMac(verifier, mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Update public key value.  It has no use after "setCertificatePath" anyway...
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.publicKey = certificatePath[0].getPublicKey();

        ///////////////////////////////////////////////////////////////////////////////////
        // Check key material for SKS compliance
        ///////////////////////////////////////////////////////////////////////////////////
        if (keyEntry.publicKey instanceof RSAPublicKey) {
            checkRsaKeyCompatibility(getRSAKeySize((RSAPublicKey) keyEntry.publicKey),
                                     ((RSAPublicKey) keyEntry.publicKey).getPublicExponent(),
                                     keyEntry.owner, keyEntry.id);
        } else {
            checkEcKeyCompatibility((ECPublicKey) keyEntry.publicKey, keyEntry.owner, keyEntry.id);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Store certificate path
        ///////////////////////////////////////////////////////////////////////////////////
        if (keyEntry.certificatePath != null) {
            keyEntry.owner.abort("Multiple calls to \"setCertificatePath\" for: " + keyEntry.id);
        }
        keyEntry.certificatePath = certificatePath.clone();
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
                                               byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession(provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Validate input as much as possible
        ///////////////////////////////////////////////////////////////////////////////////
        if (!keyEntryAlgorithm.equals(ALGORITHM_KEY_ATTEST_1)) {
            provisioning.abort("Unknown \"" + VAR_KEY_ENTRY_ALGORITHM + "\" : " + keyEntryAlgorithm, SKSException.ERROR_ALGORITHM);
        }
        Algorithm kalg = supportedAlgorithms.get(keyAlgorithm);
        if (kalg == null || (kalg.mask & ALG_KEY_GEN) == 0) {
            provisioning.abort("Unsupported \"" + VAR_KEY_ALGORITHM + "\": " + keyAlgorithm);
        }
        if ((kalg.mask & ALG_KEY_PARM) == 0 ^ keyParameters == null) {
            provisioning.abort((keyParameters == null ? "Missing" : "Unexpected") + " \"" + VAR_KEY_PARAMETERS + "\"");
        }
        if (serverSeed == null) {
            serverSeed = ZERO_LENGTH_ARRAY;
        } else if (serverSeed.length > MAX_LENGTH_SERVER_SEED) {
            provisioning.abort("\"" + VAR_SERVER_SEED + "\" length error: " + serverSeed.length);
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
                    provisioning.abort("Device PIN mixed with PIN policy ojbect");
                }
            } else {
                provisioning.abort("Unsupported: \"" + VAR_DEVICE_PIN_PROTECTION + "\"");
            }
        } else if (pinPolicyHandle != 0) {
            pinPolicy = pinPolicies.get(pinPolicyHandle);
            if (pinPolicy == null || pinPolicy.owner != provisioning) {
                provisioning.abort("Referenced PIN policy object not found");
            }
            if (enablePinCaching && pinPolicy.inputMethod != INPUT_METHOD_TRUSTED_GUI) {
                provisioning.abort("\"" + VAR_ENABLE_PIN_CACHING + "\" must be combined with \"trusted-gui\"");
            }
            pinPolicyId = pinPolicy.id;
            provisioning.names.put(pinPolicyId, true); // Referenced
            decryptPin = !pinPolicy.userDefined;
        } else {
            verifyExportDeleteProtection(deleteProtection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
            verifyExportDeleteProtection(exportProtection, EXPORT_DELETE_PROTECTION_PIN, provisioning);
            pinProtection = false;
            if (enablePinCaching) {
                provisioning.abort("\"" + VAR_ENABLE_PIN_CACHING + "\" without PIN");
            }
            if (pinValue != null) {
                provisioning.abort("\"" + VAR_PIN_VALUE + "\" expected to be empty");
            }
        }
        if (biometricProtection != BIOMETRIC_PROTECTION_NONE &&
                ((biometricProtection != BIOMETRIC_PROTECTION_EXCLUSIVE) ^ pinProtection)) {
            provisioning.abort("Invalid \"" + VAR_BIOMETRIC_PROTECTION + "\" and PIN combination");
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
        LinkedHashSet<String> tempEndorsed = new LinkedHashSet<String>();
        String prevAlg = "\0";
        for (String endorsedAlgorithm : endorsedAlgorithms) {
            ///////////////////////////////////////////////////////////////////////////////////
            // Check that the algorithms are sorted and known
            ///////////////////////////////////////////////////////////////////////////////////
            if (prevAlg.compareTo(endorsedAlgorithm) >= 0) {
                provisioning.abort("Duplicate or incorrectly sorted algorithm: " + endorsedAlgorithm);
            }
            Algorithm alg = supportedAlgorithms.get(endorsedAlgorithm);
            if (alg == null || alg.mask == 0) {
                provisioning.abort("Unsupported algorithm: " + endorsedAlgorithm);
            }
            if ((alg.mask & ALG_NONE) != 0 && endorsedAlgorithms.length > 1) {
                provisioning.abort("Algorithm must be alone: " + endorsedAlgorithm);
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
            verifyPinPolicyCompliance(false, pinValue, pinPolicy, appUsage, provisioning);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Decode key algorithm specifier
        ///////////////////////////////////////////////////////////////////////////////////
        AlgorithmParameterSpec algParSpec = null;
        if ((kalg.mask & ALG_RSA_KEY) == ALG_RSA_KEY) {
            int rsaKeySize = kalg.mask & ALG_RSA_GMSK;
            BigInteger exponent = RSAKeyGenParameterSpec.F4;
            if (keyParameters != null) {
                if (keyParameters.length == 0 || keyParameters.length > 8) {
                    provisioning.abort("\"" + VAR_KEY_PARAMETERS + "\" length error: " + keyParameters.length);
                }
                exponent = new BigInteger(keyParameters);
            }
            algParSpec = new RSAKeyGenParameterSpec(rsaKeySize, exponent);
        } else {
            algParSpec = new ECGenParameterSpec(kalg.jceName);
        }
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // At last, generate the desired key-pair
            ///////////////////////////////////////////////////////////////////////////////////
            SecureRandom secureRandom = serverSeed.length == 0 ? new SecureRandom() : new SecureRandom(serverSeed);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algParSpec instanceof RSAKeyGenParameterSpec ? "RSA" : "EC");
            kpg.initialize(algParSpec, secureRandom);
            KeyPair keyPair = kpg.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            ///////////////////////////////////////////////////////////////////////////////////
            // Create key attest
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder cka = provisioning.getMacBuilderForMethodCall(KDF_DEVICE_ATTESTATION);
            cka.addString(id);
            cka.addArray(publicKey.getEncoded());
            byte[] attestation = cka.getResult();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create a key entry
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = new KeyEntry(provisioning, id);
            provisioning.names.put(id, true); // Referenced (for "closeProvisioningSession")
            keyEntry.pinPolicy = pinPolicy;
            keyEntry.friendlyName = friendlyName;
            keyEntry.pinValue = pinValue;
            keyEntry.publicKey = publicKey;
            keyEntry.privateKey = privateKey;
            keyEntry.appUsage = appUsage;
            keyEntry.devicePinProtection = devicePinProtection;
            keyEntry.enablePinCaching = enablePinCaching;
            keyEntry.biometricProtection = biometricProtection;
            keyEntry.exportProtection = exportProtection;
            keyEntry.deleteProtection = deleteProtection;
            keyEntry.endorsedAlgorithms = tempEndorsed;
            return new KeyData(keyEntry.keyHandle, publicKey, attestation);
        } catch (GeneralSecurityException e) {
            provisioning.abort(e.getMessage(), SKSException.ERROR_INTERNAL);
        }
        return null;    // For the compiler only...
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
                                            byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession(provisioningHandle);

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
            provisioning.abort("Invalid \"" + VAR_PATTERN_RESTRICTIONS + "\" value=" + patternRestrictions);
        }
        String pukPolicyId = CRYPTO_STRING_NOT_AVAILABLE;
        PUKPolicy pukPolicy = null;
        if (pukPolicyHandle != 0) {
            pukPolicy = pukPolicies.get(pukPolicyHandle);
            if (pukPolicy == null || pukPolicy.owner != provisioning) {
                provisioning.abort("Referenced PUK policy object not found");
            }
            pukPolicyId = pukPolicy.id;
            provisioning.names.put(pukPolicyId, true); // Referenced
        }
        if ((patternRestrictions & PIN_PATTERN_MISSING_GROUP) != 0 &&
                format != PASSPHRASE_FORMAT_ALPHANUMERIC && format != PASSPHRASE_FORMAT_STRING) {
            provisioning.abort("Incorrect \"" + VAR_FORMAT + "\" for the \"missing-group\" PIN pattern policy");
        }
        if (minLength < 1 || maxLength > MAX_LENGTH_PIN_PUK || maxLength < minLength) {
            provisioning.abort("PIN policy length error");
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
        return pinPolicy.pinPolicyHandle;
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
                                            byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session
        ///////////////////////////////////////////////////////////////////////////////////
        Provisioning provisioning = getOpenProvisioningSession(provisioningHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform PUK "sanity" checks
        ///////////////////////////////////////////////////////////////////////////////////
        provisioning.passphraseFormatTest(format);
        provisioning.retryLimitTest(retryLimit, (short) 0);
        byte[] decryptedPukValue = provisioning.decrypt(pukValue);
        if (decryptedPukValue.length == 0 || decryptedPukValue.length > MAX_LENGTH_PIN_PUK) {
            provisioning.abort("PUK length error");
        }
        for (int i = 0; i < decryptedPukValue.length; i++) {
            byte c = decryptedPukValue[i];
            if ((c < '0' || c > '9') && (format == PASSPHRASE_FORMAT_NUMERIC ||
                    ((c < 'A' || c > 'Z') && format == PASSPHRASE_FORMAT_ALPHANUMERIC))) {
                provisioning.abort("PUK syntax error");
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
        return pukPolicy.pukPolicyHandle;
    }
}
