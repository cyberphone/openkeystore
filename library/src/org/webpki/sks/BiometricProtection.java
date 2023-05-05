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
package org.webpki.sks;

public enum BiometricProtection {

    NONE        ("none",        SecureKeyStore.BIOMETRIC_PROTECTION_NONE),
    ALTERNATIVE ("alternative", SecureKeyStore.BIOMETRIC_PROTECTION_ALTERNATIVE),
    COMBINED    ("combined",    SecureKeyStore.BIOMETRIC_PROTECTION_COMBINED),
    EXCLUSIVE   ("exclusive",   SecureKeyStore.BIOMETRIC_PROTECTION_EXCLUSIVE);

    private final String name;      // As expressed in protocols

    private final byte sksValue;    // As expressed in SKS

    private BiometricProtection(String name, byte sksValue) {
        this.name = name;
        this.sksValue = sksValue;
    }


    public String getProtocolName() {
        return name;
    }


    public byte getSksValue() {
        return sksValue;
    }


    public static BiometricProtection getBiometricProtectionFromString(String name) {
        for (BiometricProtection biom_type : BiometricProtection.values()) {
            if (name.equals(biom_type.name)) {
                return biom_type;
            }
        }
        throw new SKSException("Unknown \"" + SecureKeyStore.VAR_BIOMETRIC_PROTECTION + "\": " + name);
    }

}
