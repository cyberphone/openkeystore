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

import java.util.Vector;
import java.util.Set;
import java.util.EnumSet;

import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class KeyCreationRequestDecoder extends ClientDecoder {

    private static final long serialVersionUID = 1L;

    abstract class PresetValueReference {

        byte[] encryptedValue;

        PresetValueReference(JSONObjectReader rd, String nameOfKey) throws IOException {
            encryptedValue = getEncryptedKey(rd, nameOfKey);
        }

        public byte[] getEncryptedValue() {
            return encryptedValue;
        }
    }


    public class PresetPIN extends PresetValueReference {

        boolean userModifiable;

        PresetPIN(JSONObjectReader rd, String nameOfKey) throws IOException {
            super(rd, nameOfKey);
            userModifiable = rd.getBooleanConditional(USER_MODIFIABLE_JSON);
        }


        public boolean isUserModifiable() {
            return userModifiable;
        }
    }


    public class PUKPolicy extends PresetValueReference {

        byte[] mac;

        Object userData;

        PassphraseFormat format;

        short retryLimit;

        String id;

        PUKPolicy(JSONObjectReader rd) throws IOException {
            super(rd, ENCRYPTED_PUK_JSON);
            retryLimit = getAuthorizationRetryLimit(rd, 0);
            id = KeyGen2Validator.getID(rd, ID_JSON);
            format = getPassphraseFormat(rd);
            mac = KeyGen2Validator.getMac(rd);
        }


        public short getRetryLimit() {
            return retryLimit;
        }


        public PassphraseFormat getFormat() {
            return format;
        }


        public void setUserData(Object userData) {
            this.userData = userData;
        }


        public Object getUserData() {
            return userData;
        }


        public String getID() {
            return id;
        }


        public byte[] getMac() {
            return mac;
        }
    }


    public class PINPolicy {

        byte[] mac;

        String id;

        PUKPolicy pukPolicy;

        Object userData;

        PassphraseFormat format;

        short retryLimit;

        short minLength;

        short maxLength;

        Grouping grouping;

        InputMethod inputMethod;

        Set<PatternRestriction> patternRestrictions = EnumSet.noneOf(PatternRestriction.class);

        PINPolicy(JSONObjectReader rd) throws IOException {
            id = KeyGen2Validator.getID(rd, ID_JSON);

            minLength = getPINLength(rd, MIN_LENGTH_JSON);

            maxLength = getPINLength(rd, MAX_LENGTH_JSON);

            if (minLength > maxLength) {
                bad("PIN length: min > max");
            }

            retryLimit = getAuthorizationRetryLimit(rd, 1);

            format = getPassphraseFormat(rd);

            userModifiable = rd.getBooleanConditional(USER_MODIFIABLE_JSON, true);

            grouping = Grouping.getGroupingFromString(rd.getStringConditional(GROUPING_JSON, Grouping.NONE.getProtocolName()));

            inputMethod = InputMethod.getInputMethodFromString(rd.getStringConditional(INPUT_METHOD_JSON, InputMethod.ANY.getProtocolName()));

            for (String pattern : rd.hasProperty(PATTERN_RESTRICTIONS_JSON) ?
                    KeyGen2Validator.getNonEmptyList(rd, PATTERN_RESTRICTIONS_JSON)
                    :
                    new String[0]) {
                patternRestrictions.add(PatternRestriction.getPatternRestrictionFromString(pattern));
            }

            mac = KeyGen2Validator.getMac(rd);
        }


        public Set<PatternRestriction> getPatternRestrictions() {
            return patternRestrictions;
        }


        public short getMinLength() {
            return minLength;
        }


        public short getMaxLength() {
            return maxLength;
        }


        public short getRetryLimit() {
            return retryLimit;
        }


        public PassphraseFormat getFormat() {
            return format;
        }


        public Grouping getGrouping() {
            return grouping;
        }


        boolean userDefined;

        public boolean getUserDefinedFlag() {
            return userDefined;
        }


        boolean userModifiable;

        public boolean getUserModifiableFlag() {
            return userModifiable;
        }


        public InputMethod getInputMethod() {
            return inputMethod;
        }


        public String getID() {
            return id;
        }


        public byte[] getMac() {
            return mac;
        }


        public void setUserData(Object userData) {
            this.userData = userData;
        }


        public Object getUserData() {
            return userData;
        }


        public PUKPolicy getPUKPolicy() {
            return pukPolicy;
        }
    }


    public class KeyObject {

        String id;

        byte[] mac;

        boolean startOfPukGroup;

        boolean startOfPinGroup;

        PINPolicy pinPolicy;

        PresetPIN presetPin;

        byte[] userSetPin;

        boolean devicePinProtected;

        AppUsage appUsage;

        KeySpecifier keySpecifier;

        KeyObject(JSONObjectReader rd,
                  PINPolicy pinPolicy,
                  boolean startOfPinGroup,
                  PresetPIN presetPin,
                  boolean devicePinProtected) throws IOException {
            this.pinPolicy = pinPolicy;
            this.startOfPinGroup = startOfPinGroup;
            this.presetPin = presetPin;
            this.devicePinProtected = devicePinProtected;

            id = KeyGen2Validator.getID(rd, ID_JSON);

            keySpecifier = new KeySpecifier(getURI(rd, KEY_ALGORITHM_JSON),
                    rd.getBinaryConditional(KEY_PARAMETERS_JSON));

            if (rd.hasProperty(ENDORSED_ALGORITHMS_JSON)) {
                endorsedAlgorithms = getURIList(rd, ENDORSED_ALGORITHMS_JSON);
            } else {
                endorsedAlgorithms = new String[0];
            }

            serverSeed = rd.getBinaryConditional(SERVER_SEED_JSON);

            appUsage = AppUsage.getAppUsageFromString(rd.getString(APP_USAGE_JSON));

            enablePinCaching = rd.getBooleanConditional(ENABLE_PIN_CACHING_JSON);

            biometricProtection = BiometricProtection.getBiometricProtectionFromString(rd.getStringConditional(BIOMETRIC_PROTECTION_JSON,
                    BiometricProtection.NONE.getProtocolName()));

            deleteProtection = DeleteProtection.getDeletePolicyFromString(rd.getStringConditional(DELETE_PROTECTION_JSON,
                    DeleteProtection.NONE.getProtocolName()));

            exportProtection = ExportProtection.getExportPolicyFromString(rd.getStringConditional(EXPORT_PROTECTION_JSON,
                    ExportProtection.NON_EXPORTABLE.getProtocolName()));

            friendlyName = rd.getStringConditional(FRIENDLY_NAME_JSON);

            mac = KeyGen2Validator.getMac(rd);
        }


        public PINPolicy getPINPolicy() {
            return pinPolicy;
        }


        public byte[] getPresetPIN() {
            return presetPin == null ? null : presetPin.encryptedValue;
        }


        public boolean isStartOfPINPolicy() {
            return startOfPinGroup;
        }


        public boolean isStartOfPUKPolicy() {
            return startOfPukGroup;
        }


        public boolean isDevicePINProtected() {
            return devicePinProtected;
        }


        public KeySpecifier getKeySpecifier() {
            return keySpecifier;
        }


        public AppUsage getAppUsage() {
            return appUsage;
        }


        public String getID() {
            return id;
        }


        public byte[] getMac() {
            return mac;
        }


        byte[] serverSeed;

        public byte[] getServerSeed() {
            return serverSeed;
        }

        BiometricProtection biometricProtection;

        public BiometricProtection getBiometricProtection() {
            return biometricProtection;
        }


        ExportProtection exportProtection;

        public ExportProtection getExportProtection() {
            return exportProtection;
        }


        DeleteProtection deleteProtection;

        public DeleteProtection getDeleteProtection() {
            return deleteProtection;
        }


        boolean enablePinCaching;

        public boolean getEnablePINCachingFlag() {
            return enablePinCaching;
        }


        String friendlyName;

        public String getFriendlyName() {
            return friendlyName;
        }


        String[] endorsedAlgorithms;

        public String[] getEndorsedAlgorithms() {
            return endorsedAlgorithms;
        }


        public byte[] getSKSPINValue() {
            return userSetPin == null ? getPresetPIN() : userSetPin;
        }
    }

    public class UserPINError {
        public boolean lengthError;
        public boolean syntaxError;
        public boolean uniqueError;
        public AppUsage uniqueErrorAppUsage;
        public PatternRestriction patternError;
    }


    public class UserPINDescriptor {
        PINPolicy pinPolicy;
        AppUsage appUsage;

        private UserPINDescriptor(PINPolicy pinPolicy, AppUsage appUsage) {
            this.pinPolicy = pinPolicy;
            this.appUsage = appUsage;
        }

        public PINPolicy getPINPolicy() {
            return pinPolicy;
        }

        public AppUsage getAppUsage() {
            return appUsage;
        }

        public UserPINError setPIN(String pinStringValue, boolean setValueOnSuccess) {
            UserPINError error = new UserPINError();

            byte[] pin = null;
            try {
                if (pinStringValue.length() > 0 && pinPolicy.format == PassphraseFormat.BINARY) {
                    pin = DebugFormatter.getByteArrayFromHex(pinStringValue);
                } else {
                    pin = pinStringValue.getBytes("UTF-8");
                }
            } catch (IOException e) {
                error.syntaxError = true;
                return error;
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN length
            ///////////////////////////////////////////////////////////////////////////////////
            if (pinPolicy.minLength > pin.length || pinPolicy.maxLength < pin.length) {
                error.lengthError = true;
                return error;
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN syntax
            ///////////////////////////////////////////////////////////////////////////////////
            boolean upperalpha = false;
            boolean loweralpha = false;
            boolean number = false;
            boolean nonalphanum = false;
            for (int i = 0; i < pin.length; i++) {
                int c = pin[i];
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
            if ((pinPolicy.format == PassphraseFormat.NUMERIC && (loweralpha || nonalphanum || upperalpha)) ||
                (pinPolicy.format == PassphraseFormat.ALPHANUMERIC && (loweralpha || nonalphanum))) {
                error.syntaxError = true;
                return error;
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN patterns
            ///////////////////////////////////////////////////////////////////////////////////
            if (pinPolicy.patternRestrictions.contains(PatternRestriction.MISSING_GROUP)) {
                if (!upperalpha || !number ||
                    (pinPolicy.format == PassphraseFormat.STRING && (!loweralpha || !nonalphanum))) {
                    error.patternError = PatternRestriction.MISSING_GROUP;
                    return error;
                }
            }
            if (pinPolicy.patternRestrictions.contains(PatternRestriction.SEQUENCE)) {
                byte c = pin[0];
                byte f = (byte) (pin[1] - c);
                boolean seq = (f == 1) || (f == -1);
                for (int i = 1; i < pin.length; i++) {
                    if ((byte) (c + f) != pin[i]) {
                        seq = false;
                        break;
                    }
                    c = pin[i];
                }
                if (seq) {
                    error.patternError = PatternRestriction.SEQUENCE;
                    return error;
                }
            }
            if (pinPolicy.patternRestrictions.contains(PatternRestriction.REPEATED)) {
                for (int i = 0; i < pin.length; i++) {
                    byte b = pin[i];
                    for (int j = 0; j < pin.length; j++) {
                        if (j != i && b == pin[j]) {
                            error.patternError = PatternRestriction.REPEATED;
                            return error;
                        }
                    }
                }
            }
            if (pinPolicy.patternRestrictions.contains(PatternRestriction.TWO_IN_A_ROW) ||
                    pinPolicy.patternRestrictions.contains(PatternRestriction.THREE_IN_A_ROW)) {
                int max = pinPolicy.patternRestrictions.contains(PatternRestriction.THREE_IN_A_ROW) ? 3 : 2;
                byte c = pin[0];
                int sameCount = 1;
                for (int i = 1; i < pin.length; i++) {
                    if (c == pin[i]) {
                        if (++sameCount == max) {
                            error.patternError = max == 2 ? PatternRestriction.TWO_IN_A_ROW : PatternRestriction.THREE_IN_A_ROW;
                            return error;
                        }
                    } else {
                        sameCount = 1;
                        c = pin[i];
                    }
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check that PIN grouping rules are followed
            ///////////////////////////////////////////////////////////////////////////////////
            Vector<KeyObject> keysNeedingPin = new Vector<KeyObject>();
            for (KeyObject key : requestObjects) {
                if (key.pinPolicy == pinPolicy) {
                    switch (pinPolicy.grouping) {
                        case NONE:
                            if (key.userSetPin == null) {
                                keysNeedingPin.add(key);
                                break;
                            }
                            continue;

                        case SHARED:
                            keysNeedingPin.add(key);
                            continue;

                        case UNIQUE:
                            if (appUsage == key.appUsage) {
                                keysNeedingPin.add(key);
                            } else {
                                if (key.userSetPin != null && ArrayUtil.compare(pin, key.userSetPin)) {
                                    error.uniqueError = true;
                                    error.uniqueErrorAppUsage = key.appUsage;
                                    return error;
                                }
                            }
                            continue;

                        case SIGNATURE_PLUS_STANDARD:
                            if ((appUsage == AppUsage.SIGNATURE) ^ (key.appUsage == AppUsage.SIGNATURE)) {
                                if (key.userSetPin != null && ArrayUtil.compare(pin, key.userSetPin)) {
                                    error.uniqueError = true;
                                    error.uniqueErrorAppUsage = key.appUsage;
                                    return error;
                                }
                            } else {
                                keysNeedingPin.add(key);
                            }
                            continue;
                    }
                    break;
                }
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // We did it!  Assign the PIN to the associated keys or just return null=success
            ///////////////////////////////////////////////////////////////////////////////////
            if (setValueOnSuccess) {
                for (KeyObject key : keysNeedingPin) {
                    key.userSetPin = pin;
                }
            }
            return null;
        }
    }


    public Vector<KeyObject> getKeyObjects() throws IOException {
        return requestObjects;
    }


    public Vector<UserPINDescriptor> getUserPINDescriptors() {
        Vector<UserPINDescriptor> userPinPolicies = new Vector<UserPINDescriptor>();
        for (KeyObject key : requestObjects) {
            if (key.getPINPolicy() != null && key.getPINPolicy().getUserDefinedFlag()) {
                UserPINDescriptor pinDescriptor = new UserPINDescriptor(key.pinPolicy, key.appUsage);
                if (key.pinPolicy.grouping == Grouping.NONE) {
                    userPinPolicies.add(pinDescriptor);
                } else {
                    for (UserPINDescriptor upd2 : userPinPolicies) {
                        if (upd2.pinPolicy == key.pinPolicy) {
                            if (key.pinPolicy.grouping == Grouping.SHARED) {
                                pinDescriptor = null;
                                break;
                            }
                            if (key.pinPolicy.grouping == Grouping.UNIQUE) {
                                if (upd2.appUsage == key.appUsage) {
                                    pinDescriptor = null;
                                    break;
                                }
                            } else {
                                if ((upd2.appUsage == AppUsage.SIGNATURE) ^ (key.appUsage != AppUsage.SIGNATURE)) {
                                    pinDescriptor = null;
                                    break;
                                }
                            }
                        }
                    }
                    if (pinDescriptor != null) {
                        userPinPolicies.add(pinDescriptor);
                    }
                }
            }
        }
        return userPinPolicies;
    }


    private KeyObject readKeyProperties(JSONObjectReader rd,
                                        PINPolicy pinPolicy,
                                        boolean startOfPinGroup) throws IOException {
        KeyObject rk;
        PresetPIN preset = null;
        boolean save_user_defined = pinPolicy.userDefined;
        if (rd.hasProperty(ENCRYPTED_PIN_JSON)) {
            preset = new PresetPIN(rd, ENCRYPTED_PIN_JSON);
        } else {
            pinPolicy.userDefined = true;
        }
        if (!startOfPinGroup && save_user_defined ^ pinPolicy.userDefined) {
            bad("Mixed use of user-defined and preset PINs within a PIN group is not allowed");
        }
        requestObjects.add(rk = new KeyObject(rd, pinPolicy, startOfPinGroup, preset, false));
        return rk;
    }


    private void readKeyProperties(JSONObjectReader rd, boolean devicePinProtected) throws IOException {
        requestObjects.add(new KeyObject(rd, null, false, null, devicePinProtected));
    }


    private PassphraseFormat getPassphraseFormat(JSONObjectReader rd) throws IOException {
        return PassphraseFormat.getPassphraseFormatFromString(rd.getString(FORMAT_JSON));
    }


    private Vector<KeyObject> requestObjects = new Vector<KeyObject>();

    private boolean deferredIssuance;

    private String serverSessionId;

    private String clientSessionId;

    public String getClientSessionId() {
        return clientSessionId;
    }


    public String getServerSessionId() {
        return serverSessionId;
    }


    String keyEntryAlgorithm;

    public String getKeyEntryAlgorithm() {
        return keyEntryAlgorithm;
    }


    public boolean getDeferredIssuanceFlag() {
        return deferredIssuance;
    }

    @Override
    void readServerRequest(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Session properties
        /////////////////////////////////////////////////////////////////////////////////////////

        keyEntryAlgorithm = getURI(rd, KEY_ENTRY_ALGORITHM_JSON);

        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        clientSessionId = getID(rd, CLIENT_SESSION_ID_JSON);

        deferredIssuance = rd.getBooleanConditional(DEFERRED_ISSUANCE_JSON);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the key requests and protection elements [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader puk : getObjectArrayConditional(rd, PUK_POLICY_SPECIFIERS_JSON)) {
            readPINProtectedKeys(puk, new PUKPolicy(puk));
        }
        if (rd.hasProperty(PIN_POLICY_SPECIFIERS_JSON)) {
            readPINProtectedKeys(rd, null);
        }
        for (JSONObjectReader key : getObjectArrayConditional(rd, KEY_ENTRY_SPECIFIERS_JSON)) {
            readKeyProperties(key, key.getBooleanConditional(DEVICE_PIN_PROTECTION_JSON));
        }
    }

    void readPINProtectedKeys(JSONObjectReader rd, PUKPolicy pukPolicy) throws IOException {
        boolean startOfpuk = pukPolicy != null;
        for (JSONObjectReader pin : getObjectArray(rd, PIN_POLICY_SPECIFIERS_JSON)) {
            PINPolicy pinPolicy = new PINPolicy(pin);
            pinPolicy.pukPolicy = pukPolicy;
            boolean start = true;
            for (JSONObjectReader key : getObjectArray(pin, KEY_ENTRY_SPECIFIERS_JSON)) {
                readKeyProperties(key, pinPolicy, start).startOfPukGroup = startOfpuk;
                start = false;
                startOfpuk = false;
            }
        }
    }


    @Override
    public String getQualifier() {
        return KeyGen2Messages.KEY_CREATION_REQUEST.getName();
    }
}
