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
package org.webpki.webauth;

import java.io.IOException;

import org.webpki.crypto.CertificateFilter;

import org.webpki.json.JSONObjectWriter;

class CertificateFilterWriter {
    static void write(JSONObjectWriter wr, CertificateFilter cf) throws IOException {
        if (cf.getFingerPrint() != null) {
            wr.setBinary(CertificateFilter.CF_FINGER_PRINT, cf.getFingerPrint());
        }
        writeOptionalString(wr, CertificateFilter.CF_ISSUER_REG_EX, cf.getIssuerRegEx());
        writeOptionalString(wr, CertificateFilter.CF_SUBJECT_REG_EX, cf.getSubjectRegEx());
        writeOptionalString(wr, CertificateFilter.CF_EMAIL_REG_EX, cf.getEmailRegEx());
        if (cf.getSerialNumber() != null) {
            wr.setBigInteger(CertificateFilter.CF_SERIAL_NUMBER, cf.getSerialNumber());
        }
        writeOptionalList(wr, CertificateFilter.CF_POLICY_RULES, cf.getPolicyRules());
        writeOptionalList(wr, CertificateFilter.CF_KEY_USAGE_RULES, cf.getKeyUsageRules());
        writeOptionalList(wr, CertificateFilter.CF_EXT_KEY_USAGE_RULES, cf.getExtendedKeyUsageRules());
    }

    static void writeOptionalString(JSONObjectWriter wr, String name, String optional_value) throws IOException {
        if (optional_value != null) {
            wr.setString(name, optional_value);
        }
    }

    static void writeOptionalList(JSONObjectWriter wr, String name, String[] optional_values) throws IOException {
        if (optional_values != null) {
            wr.setStringArray(name, optional_values);
        }
    }
}
