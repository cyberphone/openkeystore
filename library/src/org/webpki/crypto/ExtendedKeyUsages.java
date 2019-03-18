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
package org.webpki.crypto;

import java.io.IOException;

public enum ExtendedKeyUsages {

    SERVER_AUTH             ("1.3.6.1.5.5.7.3.1", "serverAuth"),
    CLIENT_AUTH             ("1.3.6.1.5.5.7.3.2", "clientAuth"),
    CODE_SIGNING            ("1.3.6.1.5.5.7.3.3", "codeSigning"),
    EMAIL_PROTECTION        ("1.3.6.1.5.5.7.3.4", "emailProtection"),
    TIME_STAMPING           ("1.3.6.1.5.5.7.3.8", "timeStamping"),
    OCSP_SIGNING            ("1.3.6.1.5.5.7.3.9", "OCSPSigning");

    private final String oid;
    private final String x509Name;

    private ExtendedKeyUsages(String oid, String x509Name) {
        this.oid = oid;
        this.x509Name = x509Name;
    }


    public String getOID() {
        return oid;
    }


    public static ExtendedKeyUsages getExtendedKeyUsage(String x509Name) throws IOException {
        for (ExtendedKeyUsages eku : ExtendedKeyUsages.values()) {
            if (x509Name.equals(eku.x509Name)) {
                return eku;
            }
        }
        throw new IOException("Unknown EKU: " + x509Name);
    }

    public static String getOptionallyTranslatedEku(String oid) throws IOException {
        for (ExtendedKeyUsages eku : ExtendedKeyUsages.values()) {
            if (oid.equals(eku.oid)) {
                return eku.x509Name;
            }
        }
        return oid;
    }


    public Object getX509Name() {
        return x509Name;
    }
}
