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


import java.util.EnumSet;
import java.util.Set;

public class KeyProtectionInfo {

    ///////////////////////////////////////////////////////////////////////////////////
    // "ProtectionStatus" constants
    ///////////////////////////////////////////////////////////////////////////////////
    public static final byte PROTSTAT_NO_PIN        = 0x00;
    public static final byte PROTSTAT_PIN_PROTECTED = 0x01;
    public static final byte PROTSTAT_PIN_BLOCKED   = 0x04;
    public static final byte PROTSTAT_PUK_PROTECTED = 0x02;
    public static final byte PROTSTAT_PUK_BLOCKED   = 0x08;
    public static final byte PROTSTAT_DEVICE_PIN    = 0x10;

    ///////////////////////////////////////////////////////////////////////////////////
    // "KeyBackup" bit-field constants
    ///////////////////////////////////////////////////////////////////////////////////
    public static final byte KEYBACKUP_IMPORTED     = 0x01;
    public static final byte KEYBACKUP_EXPORTED     = 0x02;

    private PassphraseFormat pukFormat;

    private short pukErrorCount;

    private short pukRetryLimit;

    private boolean enablePinCaching;

    private boolean pinUserDefined;

    private boolean pinUserModifiable;

    private byte protectionStatus;

    private short pinMinLength;

    private short pinMaxLength;

    private InputMethod pinInputMethod;

    private short pinRetryLimit;

    private Grouping pinGrouping;

    private Set<PatternRestriction> pinPatternRestrictions;

    private PassphraseFormat pinFormat;

    private short pinErrorCount;

    private BiometricProtection biometricProtection;

    private byte keyBackup;

    private ExportProtection exportProtection;

    private DeleteProtection deleteProtection;

    public byte getSKSProtectionStatus() {
        return protectionStatus;
    }

    public boolean hasLocalPukProtection() {
        return (protectionStatus & PROTSTAT_PUK_PROTECTED) != 0;
    }

    public PassphraseFormat getPukFormat() throws SKSException {
        return pukFormat;
    }

    public short getPukErrorCount() {
        return pukErrorCount;
    }

    public short getPukRetryLimit() {
        return pukRetryLimit;
    }

    public boolean isPukBlocked() {
        return (protectionStatus & PROTSTAT_PUK_BLOCKED) != 0;
    }

    public boolean hasLocalPinProtection() {
        return (protectionStatus & PROTSTAT_PIN_PROTECTED) != 0;
    }

    public PassphraseFormat getPinFormat() throws SKSException {
        return pinFormat;
    }

    public Grouping getPinGrouping() throws SKSException {
        return pinGrouping;
    }

    public short getPinMinLength() {
        return pinMinLength;
    }

    public short getPinMaxLength() {
        return pinMaxLength;
    }

    public boolean getPinUserModifiableFlag() {
        return pinUserModifiable;
    }

    public boolean getPinUserDefinedFlag() {
        return pinUserDefined;
    }

    public InputMethod getPinInputMethod() {
        return pinInputMethod;
    }

    public boolean isPinBlocked() {
        return (protectionStatus & PROTSTAT_PIN_BLOCKED) != 0;
    }

    public boolean hasDevicePinProtection() {
        return (protectionStatus & PROTSTAT_DEVICE_PIN) != 0;
    }

    public short getPinErrorCount() {
        return pinErrorCount;
    }

    public short getPinRetryLimit() {
        return pinRetryLimit;
    }

    public Set<PatternRestriction> getPatternRestrictions() {
        return pinPatternRestrictions;
    }

    public BiometricProtection getBiometricProtection() {
        return biometricProtection;
    }

    public byte getKeyBackup() {
        return keyBackup;
    }

    public ExportProtection getExportProtection() {
        return exportProtection;
    }

    public DeleteProtection getDeleteProtection() {
        return deleteProtection;
    }

    public boolean getEnablePinCachingFlag() {
        return enablePinCaching;
    }

    private PassphraseFormat convertFormat(byte format) throws SKSException {
        for (PassphraseFormat kg2Format : PassphraseFormat.values()) {
            if (kg2Format.getSksValue() == format) {
                return kg2Format;
            }
        }
        throw new SKSException("Unknown format: " + format);
    }

    private InputMethod convertInputMethod(byte inputMethod) throws SKSException {
        for (InputMethod kg2InputMethod : InputMethod.values()) {
            if (kg2InputMethod.getSksValue() == inputMethod) {
                return kg2InputMethod;
            }
        }
        throw new SKSException("Unknown input method: " + inputMethod);
    }

    private ExportProtection convertExportProtection(byte exportProtection) throws SKSException {
        for (ExportProtection kg2ExportProtection : ExportProtection.values()) {
            if (kg2ExportProtection.getSksValue() == exportProtection) {
                return kg2ExportProtection;
            }
        }
        throw new SKSException("Unknown export protection: " + exportProtection);
    }

    private DeleteProtection convertDeleteProtection(byte deleteProtection) throws SKSException {
        for (DeleteProtection kg2DeleteProtection : DeleteProtection.values()) {
            if (kg2DeleteProtection.getSksValue() == deleteProtection) {
                return kg2DeleteProtection;
            }
        }
        throw new SKSException("Unknown delete protection: " + deleteProtection);
    }

    private Grouping convertGrouping(byte grouping) throws SKSException {
        for (Grouping kg2Grouping : Grouping.values()) {
            if (kg2Grouping.getSksValue() == grouping) {
                return kg2Grouping;
            }
        }
        throw new SKSException("Unknown grouping: " + grouping);
    }

    private BiometricProtection convertBiometricProtection(byte biometricProtection) throws SKSException {
        for (BiometricProtection kg2BiometricProtection : BiometricProtection.values()) {
            if (kg2BiometricProtection.getSksValue() == biometricProtection) {
                return kg2BiometricProtection;
            }
        }
        throw new SKSException("Unknown biometric protection: " + biometricProtection);
    }

    public KeyProtectionInfo(byte protectionStatus,
                             byte pukFormat,
                             short pukRetryLimit,
                             short pukErrorCount,
                             boolean userDefined,
                             boolean userModifiable,
                             byte format,
                             short retryLimit,
                             byte grouping,
                             byte patternRestrictions,
                             short minLength,
                             short maxLength,
                             byte inputMethod,
                             short pinErrorCount,
                             boolean enablePinCaching,
                             byte biometricProtection,
                             byte exportProtection,
                             byte deleteProtection,
                             byte keyBackup) throws SKSException

    {
        this.protectionStatus = protectionStatus;
        if (hasLocalPukProtection()) {
            this.pukFormat = convertFormat(pukFormat);
            this.pukErrorCount = pukErrorCount;
            this.pukRetryLimit = pukRetryLimit;
        }
        if (hasLocalPinProtection()) {
            this.pinUserDefined = userDefined;
            this.pinUserModifiable = userModifiable;
            this.pinFormat = convertFormat(format);
            this.pinRetryLimit = retryLimit;
            this.pinGrouping = convertGrouping(grouping);
            this.pinPatternRestrictions = EnumSet.noneOf(PatternRestriction.class);
            for (PatternRestriction pattern : PatternRestriction.values()) {
                if ((pattern.getSKSMaskBit() & patternRestrictions) != 0) {
                    this.pinPatternRestrictions.add(pattern);
                }
            }
            this.pinMinLength = minLength;
            this.pinMaxLength = maxLength;
            this.pinInputMethod = convertInputMethod(inputMethod);
            this.pinErrorCount = pinErrorCount;
        }
        if (hasLocalPinProtection() || hasDevicePinProtection()) {
            this.enablePinCaching = enablePinCaching;
        }
        this.keyBackup = keyBackup;
        this.biometricProtection = convertBiometricProtection(biometricProtection);
        this.exportProtection = convertExportProtection(exportProtection);
        this.deleteProtection = convertDeleteProtection(deleteProtection);
    }
}
