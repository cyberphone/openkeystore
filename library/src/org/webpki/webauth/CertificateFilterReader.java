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

import org.webpki.json.JSONObjectReader;


class CertificateFilterReader {
    static CertificateFilter read(JSONObjectReader rd) throws IOException {
        if (rd.getProperties().length == 0) {
            throw new IOException("Empty certificate filter not allowed");
        }
        CertificateFilter cf = new CertificateFilter();
        cf.setFingerPrint(rd.getBinaryConditional(CertificateFilter.CF_FINGER_PRINT));
        cf.setIssuerRegEx(rd.getStringConditional(CertificateFilter.CF_ISSUER_REG_EX));
        cf.setSubjectRegEx(rd.getStringConditional(CertificateFilter.CF_SUBJECT_REG_EX));
        cf.setEmailRegEx(rd.getStringConditional(CertificateFilter.CF_EMAIL_REG_EX));
        cf.setSerialNumber(InputValidator.getBigIntegerConditional(rd, CertificateFilter.CF_SERIAL_NUMBER));
        cf.setPolicyRules(rd.getStringArrayConditional(CertificateFilter.CF_POLICY_RULES));
        cf.setKeyUsageRules(rd.getStringArrayConditional(CertificateFilter.CF_KEY_USAGE_RULES));
        cf.setExtendedKeyUsageRules(rd.getStringArrayConditional(CertificateFilter.CF_EXT_KEY_USAGE_RULES));
        return cf;
    }
}
