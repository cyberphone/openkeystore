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

public enum ExportProtection {

    NONE           ("none",           SecureKeyStore.EXPORT_DELETE_PROTECTION_NONE),
    PIN            ("pin",            SecureKeyStore.EXPORT_DELETE_PROTECTION_PIN),
    PUK            ("puk",            SecureKeyStore.EXPORT_DELETE_PROTECTION_PUK),
    NON_EXPORTABLE ("non-exportable", SecureKeyStore.EXPORT_DELETE_PROTECTION_NOT_ALLOWED);

    private final String name;        // As expressed in protocols

    private final byte sksValue;      // As expressed in SKS

    private ExportProtection(String name, byte sksValue) {
        this.name = name;
        this.sksValue = sksValue;
    }


    public String getProtocolName() {
        return name;
    }


    public byte getSksValue() {
        return sksValue;
    }


    public static ExportProtection getExportPolicyFromString(String name) {
        for (ExportProtection exp_pol : ExportProtection.values()) {
            if (name.equals(exp_pol.name)) {
                return exp_pol;
            }
        }
        throw new SKSException("Unknown \"" + SecureKeyStore.VAR_EXPORT_PROTECTION + "\": " + name);
    }

}
