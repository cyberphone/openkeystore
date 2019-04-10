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
package org.webpki.sks.twolayer.tee;

import java.io.IOException;
import java.io.Serializable;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Vector;

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

import org.webpki.sks.twolayer.se.SECertificateData;
import org.webpki.sks.twolayer.se.SEDeviceInfo;
import org.webpki.sks.twolayer.se.SEExtensionData;
import org.webpki.sks.twolayer.se.SEKeyData;
import org.webpki.sks.twolayer.se.SEPUKData;
import org.webpki.sks.twolayer.se.SEPrivateKeyData;
import org.webpki.sks.twolayer.se.SEProvisioningData;
import org.webpki.sks.twolayer.se.SEReferenceImplementation;
import org.webpki.sks.twolayer.se.SESymmetricKeyData;

/*
 *                          ################################################
 *                          #  SKS - Secure Key Store - Two Layer Version  #
 *                          #   TEE - Trusted Execution Environment Part   #
 *                          ################################################
 *
 *  SKS is a cryptographic module that supports On-line Provisioning and Management
 *  of PKI, Symmetric keys, PINs, PUKs and Extension data.
 *  
 *  Note that persistence is not supported by the Reference Implementation.
 *
 *  Author: Anders Rundgren
 */
public class TEEReferenceImplementation implements SecureKeyStore, Serializable {
    private static final long serialVersionUID = 1L;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS version and configuration data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final String SKS_VENDOR_NAME         = "WebPKI.org";
    static final String SKS_VENDOR_DESCRIPTION  = "SKS TEE/SE RI - TEE Module";
    static final String SKS_UPDATE_URL          = null;   // Change here to test or disable
    static final boolean SKS_DEVICE_PIN_SUPPORT = false;  // Change here to test or disable
    static final boolean SKS_BIOMETRIC_SUPPORT  = false;  // Change here to test or disable
    static final int MAX_LENGTH_CRYPTO_DATA     = 16384;
    static final int MAX_LENGTH_EXTENSION_DATA  = 65536;

    /////////////////////////////////////////////////////////////////////////////////////////////
    // In virtualized environments keys may be bound to the OS + SE so that keys are unusable
    // outside of a particular instance.  The OS instance key must have high entropy and be
    // protected by the operating system.  This Reference Implementation only shows how it is
    // to be applied in a TEE/SE combo.  By setting the key to all zeros, the OS binding is
    // neutralized assuming the exclusive OR KDF mechanism is used.  The TEE is assumed to
    // be a part of the OS regardless if the OS is virtualized or not, while the SE is meant
    // to be operating at hypervisor/hardware level
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] OS_INSTANCE_KEY = 
           {(byte) 0xF4, (byte) 0xC7, (byte) 0x4F, (byte) 0x33, (byte) 0x98, (byte) 0xC4, (byte) 0x9C, (byte) 0xF4,
            (byte) 0x6D, (byte) 0x93, (byte) 0xEC, (byte) 0x98, (byte) 0x18, (byte) 0x83, (byte) 0x26, (byte) 0x61,
            (byte) 0xA4, (byte) 0x0B, (byte) 0xAE, (byte) 0x4D, (byte) 0x20, (byte) 0x4D, (byte) 0x75, (byte) 0x50,
            (byte) 0x36, (byte) 0x14, (byte) 0x10, (byte) 0x20, (byte) 0x74, (byte) 0x34, (byte) 0x69, (byte) 0x09};

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

        NameSpace(Provisioning owner, String id) {
            //////////////////////////////////////////////////////////////////////
            // Keys, PINs and PUKs share virtual ID space during provisioning
            //////////////////////////////////////////////////////////////////////
            if (owner.names.get(id) != null) {
                abort("Duplicate \"" + VAR_ID + "\" : " + id);
            }
            checkIDSyntax(id, VAR_ID);
            owner.names.put(id, false);
            this.owner = owner;
            this.id = id;
        }
    }


    static void checkIDSyntax(String identifier, String symbolic_name) {
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
            abort("Malformed \"" + symbolic_name + "\" : " + identifier);
        }
    }


    class KeyEntry extends NameSpace implements Serializable {
        private static final long serialVersionUID = 1L;

        int keyHandle;

        byte appUsage;

        PublicKey publicKey;     // In this implementation overwritten by "setCertificatePath"

        byte[] sealedKey;

        X509Certificate[] certificatePath;

        short symmetricKeyLength;

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

        byte key_backup;


        LinkedHashMap<String, ExtObject> extensions = new LinkedHashMap<String, ExtObject>();


        KeyEntry(Provisioning owner, String id) {
            super(owner, id);
            keyHandle = nextKeyHandle++;
            keys.put(keyHandle, this);
        }

        void authError() {
            abort("\"" + VAR_AUTHORIZATION + "\" error for key #" + keyHandle, SKSException.ERROR_AUTHORIZATION);
        }

        @SuppressWarnings("fallthrough")
        Vector<KeyEntry> getPINSynchronizedKeys() {
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
            for (KeyEntry keyEntry : getPINSynchronizedKeys()) {
                keyEntry.errorCount = newErrorCount;
            }
        }

        void updatePIN(byte[] newPin) {
            for (KeyEntry keyEntry : getPINSynchronizedKeys()) {
                keyEntry.pinValue = newPin;
            }
        }

        void verifyPIN(byte[] pin) {
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

        void verifyPUK(byte[] puk) {
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
                    verifyPIN(authorization);
                    return;

                case EXPORT_DELETE_PROTECTION_PUK:
                    verifyPUK(authorization);
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

        void checkCryptoDataSize(byte[] data) {
            if (data.length > MAX_LENGTH_CRYPTO_DATA) {
                abort("Exceeded \"CryptoDataSize\" for key #" + keyHandle);
            }
        }

        void setAndVerifyServerBackupFlag() {
            if ((key_backup & KeyProtectionInfo.KEYBACKUP_IMPORTED) != 0) {
                abort("Mutiple key imports for: " + id);
            }
            key_backup |= KeyProtectionInfo.KEYBACKUP_IMPORTED;
        }

        X509Certificate getEECertificate() {
            checkEECertificateAvailability();
            return certificatePath[0];
        }

        void checkEndorsedAlgorithmCompliance(String algorithm) {
            if (!endorsedAlgorithms.isEmpty() && !endorsedAlgorithms.contains(algorithm)) {
                abort("\"EndorsedAlgorithms\" for key #" + keyHandle + " does not include: " + algorithm, SKSException.ERROR_ALGORITHM);
            }
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
        LinkedHashMap<String, Boolean> names = new LinkedHashMap<String, Boolean>();

        // Post provisioning management
        Vector<PostProvisioningObject> postProvisioning_objects = new Vector<PostProvisioningObject>();

        boolean privacyEnabled;
        String clientSessionId;
        String serverSessionId;
        String issuerUri;
        boolean open = true;
        PublicKey keyManagementKey;
        int clientTime;
        int sessionLifeTime;
        short sessionKeyLimit;

        byte[] provisioningState;

        Provisioning() {
            provisioningHandle = nextProvHandle++;
            provisionings.put(provisioningHandle, this);
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

        void addPostProvisioningObject(KeyEntry targetKeyEntry, KeyEntry newKey, boolean upd_orDel) {
            ///////////////////////////////////////////////////////////////////////////////////
            // "Sanity checks"
            ///////////////////////////////////////////////////////////////////////////////////
            if (privacyEnabled ^ targetKeyEntry.owner.privacyEnabled) {
                abort("Inconsistent use of the \"" + VAR_PRIVACY_ENABLED + "\" attribute for key #" + targetKeyEntry.keyHandle);
            }
            for (PostProvisioningObject post_op : postProvisioning_objects) {
                if (post_op.newKey != null && post_op.newKey == newKey) {
                    abort("New key used for multiple operations: " + newKey.id);
                }
                if (post_op.targetKeyEntry == targetKeyEntry) {
                    ////////////////////////////////////////////////////////////////////////////////////////////////
                    // Multiple targeting of the same old key is OK but has restrictions
                    ////////////////////////////////////////////////////////////////////////////////////////////////
                    if ((newKey == null && upd_orDel) || (post_op.newKey == null && post_op.upd_orDel)) // postDeleteKey
                    {
                        abort("Delete wasn't exclusive for key #" + targetKeyEntry.keyHandle);
                    } else if (newKey == null && post_op.newKey == null) // postUnlockKey * 2
                    {
                        abort("Multiple unlocks of key #" + targetKeyEntry.keyHandle);
                    } else if (upd_orDel && post_op.upd_orDel) {
                        abort("Multiple updates of key #" + targetKeyEntry.keyHandle);
                    }
                }
            }
            postProvisioning_objects.add(new PostProvisioningObject(targetKeyEntry, newKey, upd_orDel));
        }

        void rangeTest(byte value, byte lowLimit, byte highLimit, String object_name) {
            if (value > highLimit || value < lowLimit) {
                abort("Invalid \"" + object_name + "\" value=" + value);
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
    }


    class PostProvisioningObject implements Serializable {
        private static final long serialVersionUID = 1L;

        KeyEntry targetKeyEntry;
        KeyEntry newKey;      // null for postDeleteKey and postUnlockKey
        boolean upd_orDel;    // true for postUpdateKey and postDeleteKey

        PostProvisioningObject(KeyEntry targetKeyEntry, KeyEntry newKey, boolean upd_orDel) {
            this.targetKeyEntry = targetKeyEntry;
            this.newKey = newKey;
            this.upd_orDel = upd_orDel;
        }
    }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // Utility Functions
    /////////////////////////////////////////////////////////////////////////////////////////////

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

    byte[] getBinary(String string) {
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
    
    @SuppressWarnings("fallthrough")
    void verifyPINPolicyCompliance(boolean forcedSetter, 
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

    void testUpdatablePIN(KeyEntry keyEntry, byte[] newPin) {
        if (!keyEntry.pinPolicy.userModifiable) {
            abort("PIN for key #" + keyEntry.keyHandle + " is not user modifiable", SKSException.ERROR_NOT_ALLOWED);
        }
        verifyPINPolicyCompliance(true, newPin, keyEntry.pinPolicy, keyEntry.appUsage);
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

    byte[] addArrays(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    void verifyExportDeleteProtection(byte actualProtection, 
                                      byte minProtection_val,
                                      Provisioning provisioning) {
        if (actualProtection >= minProtection_val && actualProtection <= EXPORT_DELETE_PROTECTION_PUK) {
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
            // Verify incoming MAC and target key data through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            X509Certificate eeCertificate = newKey.getEECertificate();
            provisioning.provisioningState =
                SEReferenceImplementation.validateTargetKey2(OS_INSTANCE_KEY,
                                                             targetKeyEntry.getEECertificate(),
                                                             targetKeyHandle,
                                                             targetKeyEntry.owner.keyManagementKey,
                                                             eeCertificate,
                                                             newKey.sealedKey,
                                                             provisioning.privacyEnabled,
                                                             update ? 
                                             METHOD_POST_UPDATE_KEY : METHOD_POST_CLONE_KEY_PROTECTION,
                                                             authorization,
                                                             provisioning.provisioningState,
                                                             mac).getByteArray();

            ///////////////////////////////////////////////////////////////////////////////////
            // Put the operation in the post-op buffer used by "closeProvisioningSession"
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.addPostProvisioningObject(targetKeyEntry, newKey, update);
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
            // Verify incoming MAC and target key data through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.provisioningState =
                SEReferenceImplementation.validateTargetKey(OS_INSTANCE_KEY,
                                                            targetKeyEntry.getEECertificate(),
                                                            targetKeyHandle,
                                                            targetKeyEntry.owner.keyManagementKey,
                                                            provisioning.privacyEnabled,
                                                            delete ? 
                                            METHOD_POST_DELETE_KEY : METHOD_POST_UNLOCK_KEY,
                                                            authorization,
                                                            provisioning.provisioningState,
                                                            mac).getByteArray();

            ///////////////////////////////////////////////////////////////////////////////////
            // Put the operation in the post-op buffer used by "closeProvisioningSession"
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.addPostProvisioningObject(targetKeyEntry, null, delete);
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
        keyEntry.verifyPUK(authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Reset PIN error counter(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.setErrorCounter((short) 0);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               changePIN                                    //
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
        keyEntry.verifyPIN(authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Test new PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePIN(keyEntry, newPin);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Set PIN value(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.updatePIN(newPin);
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                                 setPIN                                     //
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
        keyEntry.verifyPUK(authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Test new PIN
        ///////////////////////////////////////////////////////////////////////////////////
        testUpdatablePIN(keyEntry, newPin);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success!  Set PIN value(s) and unlock associated key(s)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.updatePIN(newPin);
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
        try {
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
            keyEntry.key_backup |= KeyProtectionInfo.KEYBACKUP_EXPORTED;
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Export key in raw unencrypted format through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            return SEReferenceImplementation.unwrapKey(OS_INSTANCE_KEY, keyEntry.sealedKey).getByteArray();
        } catch (Exception e) {
            abort(e.getMessage());
            return null;   // For the compiler...
        }
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
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Lookup the extension(s) bound to the key
        ///////////////////////////////////////////////////////////////////////////////////
        ExtObject ext_obj = keyEntry.extensions.get(type);
        if (ext_obj == null || ext_obj.subType != SUB_TYPE_PROPERTY_BAG) {
            abort("No such \"" + VAR_PROPERTY_BAG + "\" : " + type);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Found, now look for the property name and update the associated value
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] bin_name = getBinary(name);
        byte[] binValue = getBinary(value);
        int i = 0;
        while (i < ext_obj.extensionData.length) {
            int namLen = getShort(ext_obj.extensionData, i);
            i += 2;
            byte[] pname = Arrays.copyOfRange(ext_obj.extensionData, i, namLen + i);
            i += namLen;
            int valLen = getShort(ext_obj.extensionData, i + 1);
            if (Arrays.equals(bin_name, pname)) {
                if (ext_obj.extensionData[i] != 0x01) {
                    abort("\"" + VAR_PROPERTY + "\" not writable: " + name, SKSException.ERROR_NOT_ALLOWED);
                }
                ext_obj.extensionData = addArrays(addArrays(Arrays.copyOfRange(ext_obj.extensionData, 0, ++i),
                        addArrays(new byte[]{(byte) (binValue.length >> 8), (byte) binValue.length}, binValue)),
                        Arrays.copyOfRange(ext_obj.extensionData, i + valLen + 2, ext_obj.extensionData.length));
                return;
            }
            i += valLen + 3;
        }
        abort("\"" + VAR_PROPERTY + "\" not found: " + name);
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
        ExtObject ext_obj = keyEntry.extensions.get(type);
        if (ext_obj == null) {
            abort("No such extension: " + type + " for key #" + keyHandle);
        }
        return new Extension(ext_obj.subType, ext_obj.qualifier, ext_obj.extensionData);
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
                                                    byte[] data) {
        try {
        ///////////////////////////////////////////////////////////////////////////////////
        // Get key (which must belong to an already fully provisioned session)
        ///////////////////////////////////////////////////////////////////////////////////
        KeyEntry keyEntry = getStdKey(keyHandle);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify PIN (in any)
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.verifyPIN(authorization);

        ///////////////////////////////////////////////////////////////////////////////////
        // Endorsed algorithm compliance is enforced at the TEE level
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.checkEndorsedAlgorithmCompliance(algorithm);

        ///////////////////////////////////////////////////////////////////////////////////
        // Execute it!
        ///////////////////////////////////////////////////////////////////////////////////
        return SEReferenceImplementation.executeAsymmetricDecrypt(OS_INSTANCE_KEY,
                                                                  keyEntry.sealedKey,
                                                                  keyHandle,
                                                                  algorithm,
                                                                  parameters,
                                                                  data).getByteArray();
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
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
                                              byte[] data) {
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key (which must belong to an already fully provisioned session)
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = getStdKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify PIN (in any)
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.verifyPIN(authorization);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Enforce the data limit
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.checkCryptoDataSize(data);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Endorsed algorithm compliance is enforced at the TEE level
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.checkEndorsedAlgorithmCompliance(algorithm);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Execute it!
            ///////////////////////////////////////////////////////////////////////////////////
            return SEReferenceImplementation.executeSignHash(OS_INSTANCE_KEY,
                                                             keyEntry.sealedKey,
                                                             keyHandle,
                                                             algorithm,
                                                             parameters,
                                                             data).getByteArray();
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
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
                                            ECPublicKey publicKey) {
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key (which must belong to an already fully provisioned session)
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = getStdKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify PIN (in any)
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.verifyPIN(authorization);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Endorsed algorithm compliance is enforced at the TEE level
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.checkEndorsedAlgorithmCompliance(algorithm);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Execute it!
            ///////////////////////////////////////////////////////////////////////////////////
            return SEReferenceImplementation.executeKeyAgreement(OS_INSTANCE_KEY,
                                                                 keyEntry.sealedKey,
                                                                 keyHandle,
                                                                 algorithm,
                                                                 parameters,
                                                                 publicKey).getByteArray();
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
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
                                                   byte[] data) {
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key (which must belong to an already fully provisioned session)
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = getStdKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify PIN (in any)
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.verifyPIN(authorization);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Enforce the data limit
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.checkCryptoDataSize(data);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Endorsed algorithm compliance is enforced at the TEE level
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.checkEndorsedAlgorithmCompliance(algorithm);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Execute it!
            ///////////////////////////////////////////////////////////////////////////////////
            return SEReferenceImplementation.executeSymmetricEncryption(OS_INSTANCE_KEY,
                                                                        keyEntry.sealedKey,
                                                                        keyHandle,
                                                                        algorithm,
                                                                        mode,
                                                                        parameters,
                                                                        data).getByteArray();
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               performHMAC                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] performHmac(int keyHandle,
                                           String algorithm,
                                           byte[] parameters,
                                           byte[] authorization,
                                           byte[] data) {
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get key (which must belong to an already fully provisioned session)
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = getStdKey(keyHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify PIN (in any)
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.verifyPIN(authorization);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Enforce the data limit
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.checkCryptoDataSize(data);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Endorsed algorithm compliance is enforced at the TEE level
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.checkEndorsedAlgorithmCompliance(algorithm);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Execute it!
            ///////////////////////////////////////////////////////////////////////////////////
            return SEReferenceImplementation.executeHMAC(OS_INSTANCE_KEY,
                                                         keyEntry.sealedKey,
                                                         keyHandle,
                                                         algorithm,
                                                         parameters,
                                                         data).getByteArray();
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
        try {
            SEDeviceInfo deviceInfo = SEReferenceImplementation.getDeviceInfo();
            return new DeviceInfo(deviceInfo.getApiLevel(),
                                  deviceInfo.getDeviceType(),
                                  deviceInfo.getUpdateUrl(),
                                  SKS_VENDOR_NAME + " / " + deviceInfo.getVendorName(),
                                  SKS_VENDOR_DESCRIPTION + " / " + deviceInfo.getVendorDescription(),
                                  deviceInfo.getCertificatePath(),
                                  deviceInfo.getSupportedAlgorithms(),
                                  deviceInfo.getCryptoDataSize(),
                                  deviceInfo.getExtensionDataSize(),
                                  SKS_DEVICE_PIN_SUPPORT,
                                  SKS_BIOMETRIC_SUPPORT);
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
        }
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
        byte puk_format = 0;
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
                puk_format = keyEntry.pinPolicy.pukPolicy.format;
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
                                     puk_format,
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
                                     keyEntry.key_backup);
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
        return new KeyAttributes(keyEntry.symmetricKeyLength,
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
        Provisioning provisioning = null;
        try {
            provisioning = getClosedProvisioningSession(provisioningHandle);
            if (provisioning.keyManagementKey == null) {
                abort("Session is not updatable: " + provisioningHandle, SKSException.ERROR_NOT_ALLOWED);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify KMK signature
            ///////////////////////////////////////////////////////////////////////////////////
            if (!SEReferenceImplementation.validateRollOverAuthorization(keyManagementKey,
                                                                         provisioning.keyManagementKey,
                                                                         authorization).getBoolean()) {
                abort("\"" + VAR_AUTHORIZATION + "\" signature did not verify for session: " + 
                      provisioningHandle);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, update KeyManagementKey
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.keyManagementKey = keyManagementKey;
        } catch (Exception e) {
            tearDownSession(provisioning, e);
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
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        closeProvisioningSession                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    @Override
    public synchronized byte[] closeProvisioningSession(int provisioningHandle,
                                                        byte[] challenge,
                                                        byte[] mac) {
        Provisioning provisioning = null;
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Get provisioning session
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning = getOpenProvisioningSession(provisioningHandle);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Generate the attestation in advance => checking SessionKeyLimit before "commit"
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] attestation =
                SEReferenceImplementation.closeProvisioningAttest(OS_INSTANCE_KEY,
                                                                  provisioning.provisioningState,
                                                                  provisioning.serverSessionId,
                                                                  provisioning.clientSessionId,
                                                                  provisioning.issuerUri,
                                                                  challenge,
                                                                  mac).getByteArray();
    
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
                    if (keyEntry.symmetricKeyLength == 0) {
                        SEReferenceImplementation.checkKeyPair(OS_INSTANCE_KEY,
                                                               keyEntry.sealedKey,
                                                               keyEntry.publicKey,
                                                               keyEntry.id);
                    }
    
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Test that there are no collisions
                    ///////////////////////////////////////////////////////////////////////////////////
                    for (KeyEntry keyEntry_temp : keys.values()) {
                        if (keyEntry_temp.keyHandle != keyEntry.keyHandle && keyEntry_temp.certificatePath != null &&
                            keyEntry_temp.certificatePath[0].equals(keyEntry.certificatePath[0])) {
                            ///////////////////////////////////////////////////////////////////////////////////
                            // There was a conflict, ignore updates/deletes
                            ///////////////////////////////////////////////////////////////////////////////////
                            boolean collision = true;
                            for (PostProvisioningObject post_op : provisioning.postProvisioning_objects) {
                                if (post_op.targetKeyEntry == keyEntry_temp && post_op.upd_orDel) {
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
                        SEReferenceImplementation.testKeyAndAlgorithmCompliance(OS_INSTANCE_KEY,
                                                                                keyEntry.sealedKey,
                                                                                algorithm,
                                                                                keyEntry.id)
                            .testReturn();
                    }
                }
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Post provisioning 1: Check that all the target keys are still there...
            ///////////////////////////////////////////////////////////////////////////////////
            for (PostProvisioningObject post_op : provisioning.postProvisioning_objects) {
                provisioning.getTargetKey(post_op.targetKeyEntry.keyHandle);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Post provisioning 2: Perform operations
            ///////////////////////////////////////////////////////////////////////////////////
            for (PostProvisioningObject post_op : provisioning.postProvisioning_objects) {
                KeyEntry keyEntry = post_op.targetKeyEntry;
                if (post_op.newKey == null) {
                    if (post_op.upd_orDel) {
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
                    post_op.newKey.pinPolicy = keyEntry.pinPolicy;
                    post_op.newKey.pinValue = keyEntry.pinValue;
                    post_op.newKey.errorCount = keyEntry.errorCount;
                    post_op.newKey.devicePinProtection = keyEntry.devicePinProtection;
    
                    if (post_op.upd_orDel) {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // postUpdateKey. Store new key in the place of the old
                        ///////////////////////////////////////////////////////////////////////////////////
                        keys.put(keyEntry.keyHandle, post_op.newKey);
    
                        ///////////////////////////////////////////////////////////////////////////////////
                        // Remove space occupied by the new key and restore old key handle
                        ///////////////////////////////////////////////////////////////////////////////////
                        keys.remove(post_op.newKey.keyHandle);
                        post_op.newKey.keyHandle = keyEntry.keyHandle;
                    }
                }
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Post provisioning 3: Take ownership of managed keys and their associates
            ///////////////////////////////////////////////////////////////////////////////////
            for (PostProvisioningObject post_op : provisioning.postProvisioning_objects) {
                Provisioning old_owner = post_op.targetKeyEntry.owner;
                if (old_owner == provisioning) {
                    continue;
                }
                for (KeyEntry keyEntry : keys.values()) {
                    if (keyEntry.owner == old_owner) {
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
                provisionings.remove(old_owner.provisioningHandle);  // OK to perform also if already done
            }
            provisioning.postProvisioning_objects.clear();  // No need to save
    
            ///////////////////////////////////////////////////////////////////////////////////
            // If there are no keys associated with the session we just delete it
            ///////////////////////////////////////////////////////////////////////////////////
            deleteEmptySession(provisioning);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // We are done, close the show for this time
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.open = false;
            return attestation;
        } catch (Exception e) {
            tearDownSession(provisioning, e);
            return null;   // For the compiler...
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
                                                                      int sessionLifeTime,
                                                                      short sessionKeyLimit,
                                                                      byte[] serverCertificate) {
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Limited input validation
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(serverSessionId, VAR_SERVER_SESSION_ID);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // The assumption here is that the SE can do crypto parameter validation...
            ///////////////////////////////////////////////////////////////////////////////////
            SEProvisioningData sePd = 
                SEReferenceImplementation.createProvisioningData(OS_INSTANCE_KEY,
                                                                 sessionKeyAlgorithm,
                                                                 privacyEnabled,
                                                                 serverSessionId,
                                                                 serverEphemeralKey,
                                                                 issuerUri,
                                                                 keyManagementKey,
                                                                 clientTime,
                                                                 sessionLifeTime,
                                                                 sessionKeyLimit,
                                                                 serverCertificate);
     
            ///////////////////////////////////////////////////////////////////////////////////
            // We did it!
            ///////////////////////////////////////////////////////////////////////////////////
            Provisioning provisioning = new Provisioning();
            provisioning.privacyEnabled = privacyEnabled;
            provisioning.serverSessionId = serverSessionId;
            provisioning.clientSessionId = sePd.getClientSessionId();
            provisioning.issuerUri = issuerUri;
            provisioning.keyManagementKey = keyManagementKey;
            provisioning.clientTime = clientTime;
            provisioning.sessionLifeTime = sessionLifeTime;
            provisioning.provisioningState = sePd.getProvisioningState();
            return new ProvisioningSession(provisioning.provisioningHandle,
                                           sePd.getClientSessionId(),
                                           sePd.getAttestation(),
                                           sePd.getClientEphemeralKey());
        } catch (Exception e) {
            abort(e);
            return null;   // For the compiler...
        }
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
            keyEntry.owner.rangeTest(subType, SUB_TYPE_EXTENSION, SUB_TYPE_LOGOTYPE, "SubType");
            if (type.length() == 0 || type.length() > MAX_LENGTH_URI) {
                abort("URI length error: " + type.length());
            }
            if (keyEntry.extensions.get(type) != null) {
                abort("Duplicate \"" + VAR_TYPE + "\" : " + type);
            }
            if (extensionData.length > (subType == SUB_TYPE_ENCRYPTED_EXTENSION ?
                    MAX_LENGTH_EXTENSION_DATA + AES_CBC_PKCS5_PADDING
                    :
                    MAX_LENGTH_EXTENSION_DATA)) {
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
            // Verify incoming MAC through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            X509Certificate eeCertificate = keyEntry.getEECertificate();
            SEExtensionData seExtensionData = 
                SEReferenceImplementation.verifyAndGetExtension(OS_INSTANCE_KEY,
                                                                keyEntry.owner.provisioningState,
                                                                keyEntry.sealedKey,
                                                                keyEntry.id,
                                                                eeCertificate,
                                                                type,
                                                                subType,
                                                                binQualifier,
                                                                extensionData,
                                                                mac);
            keyEntry.owner.provisioningState = seExtensionData.getProvisioningState();
            extensionData = seExtensionData.getExtensionData();
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Succeeded, create object
            ///////////////////////////////////////////////////////////////////////////////////
            ExtObject extension = new ExtObject();
            extension.subType = subType;
            extension.qualifier = qualifier;
            extension.extensionData = extensionData;
            keyEntry.extensions.put(type, extension);
        } catch (Exception e) {
            abort(e);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           importPrivateKey                                 //
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
            // Mark as "copied" by the server
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.setAndVerifyServerBackupFlag();
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify MAC and import private key through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            X509Certificate eeCertificate = keyEntry.getEECertificate();
            SEPrivateKeyData sePrivateKeyData =
                SEReferenceImplementation.verifyAndImportPrivateKey(OS_INSTANCE_KEY,
                                                                    keyEntry.owner.provisioningState,
                                                                    keyEntry.sealedKey,
                                                                    keyEntry.id,
                                                                    eeCertificate,
                                                                    encryptedKey,
                                                                    mac);
            keyEntry.owner.provisioningState = sePrivateKeyData.getProvisioningState();
            keyEntry.sealedKey = sePrivateKeyData.getSealedKey();
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
                abort("Symmetric key: " + keyEntry.id + " exceeds " + MAX_LENGTH_SYMMETRIC_KEY + " bytes");
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Mark as "copied" by the server and set the symmetric flag
            ///////////////////////////////////////////////////////////////////////////////////
            keyEntry.setAndVerifyServerBackupFlag();
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify MAC and import symmetric key through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            X509Certificate eeCertificate = keyEntry.getEECertificate();
            SESymmetricKeyData seSymmetricKeyData =
                SEReferenceImplementation.verifyAndImportSymmetricKey(OS_INSTANCE_KEY,
                                                                      keyEntry.owner.provisioningState,
                                                                      keyEntry.sealedKey,
                                                                      keyEntry.id,
                                                                      eeCertificate,
                                                                      encryptedKey,
                                                                      mac);
            keyEntry.owner.provisioningState = seSymmetricKeyData.getProvisioningState();
            keyEntry.symmetricKeyLength = seSymmetricKeyData.getSymmetricKeyLength();
            keyEntry.sealedKey = seSymmetricKeyData.getSealedKey();
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
            // Verify MAC through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            SECertificateData seCertificateData =
                SEReferenceImplementation.setAndVerifyCertificatePath(OS_INSTANCE_KEY,
                                                                      keyEntry.owner.provisioningState,
                                                                      keyEntry.sealedKey,
                                                                      keyEntry.id,
                                                                      keyEntry.publicKey,
                                                                      certificatePath,
                                                                      mac);
            keyEntry.owner.provisioningState = seCertificateData.getProvisioningState();
            keyEntry.sealedKey = seCertificateData.getSealedKey();
        } catch (Exception e) {
            tearDownSession(keyEntry, e);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Update public key value.  It has no use after "setCertificatePath" anyway...
        ///////////////////////////////////////////////////////////////////////////////////
        keyEntry.publicKey = certificatePath[0].getPublicKey();

        ///////////////////////////////////////////////////////////////////////////////////
        // Store certificate path
        ///////////////////////////////////////////////////////////////////////////////////
        if (keyEntry.certificatePath != null) {
            abort("Multiple calls to \"setCertificatePath\" for: " + keyEntry.id);
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
            if (serverSeed != null && (serverSeed.length == 0 || serverSeed.length > MAX_LENGTH_SERVER_SEED)) {
                abort("\"" + VAR_SERVER_SEED + "\" length error: " + serverSeed.length);
            }
            provisioning.rangeTest(exportProtection, EXPORT_DELETE_PROTECTION_NONE, EXPORT_DELETE_PROTECTION_NOT_ALLOWED, "ExportProtection");
            provisioning.rangeTest(deleteProtection, EXPORT_DELETE_PROTECTION_NONE, EXPORT_DELETE_PROTECTION_NOT_ALLOWED, "DeleteProtection");
            provisioning.rangeTest(appUsage, APP_USAGE_SIGNATURE, APP_USAGE_UNIVERSAL, "AppUsage");
            provisioning.rangeTest(biometricProtection, BIOMETRIC_PROTECTION_NONE, BIOMETRIC_PROTECTION_EXCLUSIVE, "BiometricProtection");
    
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
                abort("Invalid \"BiometricProtection\" and PIN combination");
            }
            if (pinPolicy == null || pinPolicy.pukPolicy == null) {
                verifyExportDeleteProtection(deleteProtection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
                verifyExportDeleteProtection(exportProtection, EXPORT_DELETE_PROTECTION_PUK, provisioning);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify MAC and get keys through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            SEKeyData seKeyData = null;
            seKeyData = SEReferenceImplementation.createKeyPair(OS_INSTANCE_KEY,
                                                                provisioning.provisioningState,
                                                                id,
                                                                keyEntryAlgorithm,
                                                                serverSeed,
                                                                devicePinProtection,
                                                                pinPolicyId,
                                                                decryptPin ? pinValue : null,
                                                                enablePinCaching,
                                                                biometricProtection,
                                                                exportProtection,
                                                                deleteProtection,
                                                                appUsage,
                                                                friendlyName,
                                                                keyAlgorithm,
                                                                keyParameters,
                                                                endorsedAlgorithms,
                                                                mac);
            provisioning.provisioningState = seKeyData.getProvisioningState();

            ///////////////////////////////////////////////////////////////////////////////////
            // Perform a gazillion tests on PINs if applicable
            ///////////////////////////////////////////////////////////////////////////////////
            if (decryptPin) {
                pinValue = seKeyData.getDecryptedPinValue();
            } else if (pinValue != null) {
                pinValue = pinValue.clone();
            }
            if (pinPolicy != null) {
                ///////////////////////////////////////////////////////////////////////////////////
                // Testing the actual PIN value
                ///////////////////////////////////////////////////////////////////////////////////
                verifyPINPolicyCompliance(false, pinValue, pinPolicy, appUsage);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create a key entry
            ///////////////////////////////////////////////////////////////////////////////////
            KeyEntry keyEntry = new KeyEntry(provisioning, id);
            provisioning.names.put(id, true); // Referenced (for "closeProvisioningSession")
            keyEntry.pinPolicy = pinPolicy;
            keyEntry.friendlyName = friendlyName;
            keyEntry.pinValue = pinValue;
            keyEntry.publicKey = seKeyData.getPublicKey();
            keyEntry.sealedKey = seKeyData.getSealedKey();
            keyEntry.appUsage = appUsage;
            keyEntry.devicePinProtection = devicePinProtection;
            keyEntry.enablePinCaching = enablePinCaching;
            keyEntry.biometricProtection = biometricProtection;
            keyEntry.exportProtection = exportProtection;
            keyEntry.deleteProtection = deleteProtection;
            LinkedHashSet<String> tempEndorsed = new LinkedHashSet<String>();
            for (String endorsedAlgorithm : endorsedAlgorithms) {
                tempEndorsed.add(endorsedAlgorithm);
            }
            keyEntry.endorsedAlgorithms = tempEndorsed;
            return new KeyData(keyEntry.keyHandle, seKeyData.getPublicKey(), seKeyData.getAttestation());
        } catch (Exception e) {
            tearDownSession(provisioning, e);
            return null;  // For the compiler...
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            createPINPolicy                                 //
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
            provisioning.rangeTest(grouping, PIN_GROUPING_NONE, PIN_GROUPING_UNIQUE, "Grouping");
            provisioning.rangeTest(inputMethod, INPUT_METHOD_ANY, INPUT_METHOD_TRUSTED_GUI, "InputMethod");
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
            // Verify MAC through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            provisioning.provisioningState =
                SEReferenceImplementation.verifyPINPolicy(OS_INSTANCE_KEY,
                                                          provisioning.provisioningState,
                                                          id,
                                                          pukPolicyId,
                                                          userDefined,
                                                          userModifiable,
                                                          format,
                                                          retryLimit,
                                                          grouping,
                                                          patternRestrictions,
                                                          minLength,
                                                          maxLength,
                                                          inputMethod,
                                                          mac).getByteArray();

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
        } catch (Exception e) {
            tearDownSession(provisioning, e);
            return 0;    // For the compiler...
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            createPUKPolicy                                 //
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
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify MAC and get the decrypted value through the SE
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] decryptedPukValue = null;
            SEPUKData sePukData = SEReferenceImplementation.getPUKValue(OS_INSTANCE_KEY,
                                                                        provisioning.provisioningState,
                                                                        id,
                                                                        pukValue,
                                                                        format,
                                                                        retryLimit,
                                                                        mac);
            provisioning.provisioningState = sePukData.getProvisioningState();
            decryptedPukValue = sePukData.getPukValue();
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
            // Success, create object
            ///////////////////////////////////////////////////////////////////////////////////
            PUKPolicy pukPolicy = new PUKPolicy(provisioning, id);
            pukPolicy.pukValue = decryptedPukValue;
            pukPolicy.format = format;
            pukPolicy.retryLimit = retryLimit;
            return pukPolicy.pukPolicyHandle;
        } catch (Exception e) {
            tearDownSession(provisioning, e);
            return 0;  // For the compiler...
        }
    }
}
