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
package org.webpki.securityproxy;

import java.security.cert.X509Certificate;

import java.util.Vector;

/**
 * Predefined trust-anchor upload payload
 */
public class UploadedTrustStore implements JavaUploadInterface {
    private static final long serialVersionUID = 1L;

    Vector<X509Certificate> certs = new Vector<X509Certificate>();

    public void addCertificate(X509Certificate cert) {
        certs.add(cert);
    }

    public X509Certificate[] getCertificates() {
        return certs.toArray(new X509Certificate[0]);
    }

}
