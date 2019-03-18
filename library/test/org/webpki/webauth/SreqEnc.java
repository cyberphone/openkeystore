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

import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.HashAlgorithms;


public class SreqEnc {
    static CertificateFilter[] createCertificateFilters() throws Exception {
        KeyStore ks = DemoKeyStore.getMarionKeyStore();
        X509Certificate cert = (X509Certificate) ks.getCertificateChain("mykey")[1];

        CertificateFilter cf1 = new CertificateFilter()
                .setPolicyRules(new String[]{"1.25.453.22.22.88"})
                .setKeyUsageRules(new String[]{"digitalSignature"})
                .setFingerPrint(HashAlgorithms.SHA256.digest(cert.getEncoded()))  // CA
                .setIssuer(cert.getIssuerX500Principal());

        CertificateFilter cf2 = new CertificateFilter()
                .setFingerPrint(HashAlgorithms.SHA256.digest(new byte[]{1, 4, 5, 3, 6, 7, 8, 3, 0, 3, 5, 6, 1, 4, 5, 3, 6, 7, 8, 3}))
                .setIssuer(new X500Principal("CN=SuckerTrust GlobalCA, emailaddress=boss@fire.hell, c=TV"))
                .setExtendedKeyUsageRules(new String[]{"1.56.245.123"})
                .setKeyUsageRules(new String[]{"nonRepudiation", "-keyEncipherment"})
                .setEmail("try@this.com");
        return new CertificateFilter[]{cf1, cf2};
    }

}
