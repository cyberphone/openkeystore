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


import org.webpki.util.DebugFormatter;

import org.webpki.crypto.CertificateFilter;

public class SreqDec {

    static void printcf(CertificateFilter cf, StringBuilder s) {
        s.append("\nCERTFILTER:");
        if (cf.getFingerPrint() != null)
            s.append("\nSha1=" + DebugFormatter.getHexString(cf.getFingerPrint()));
        if (cf.getIssuerRegEx() != null) s.append("\nIssuer=" + cf.getIssuerRegEx());
        if (cf.getSubjectRegEx() != null) s.append("\nSubject=" + cf.getSubjectRegEx());
        if (cf.getSerialNumber() != null) s.append("\nSerial=" + cf.getSerialNumber());
        if (cf.getPolicyRules() != null) s.append("\nPolicy=" + cf.getPolicyRules());
        if (cf.getKeyUsageRules() != null) s.append("\nKeyUsage=" + cf.getKeyUsageRules());
        if (cf.getExtendedKeyUsageRules() != null)
            s.append("\nExtKeyUsage=" + cf.getExtendedKeyUsageRules());
        s.append("\nCERTFILTER\n");
    }

}
