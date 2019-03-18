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
package org.webpki.xmldsig;

import java.io.IOException;

import java.security.cert.X509Certificate;

import java.security.GeneralSecurityException;

import javax.security.auth.x500.X500Principal;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateUtil;

public class XMLVerifier extends XMLVerifierCore {
    private X509Certificate[] certpath;

    private VerifierInterface verifier_interface;


    private void badCertMatch() throws IOException {
        throw new IOException("Signing certificate specifier(s) do not match actual signer cert: " +
                certpath[0].getSubjectX500Principal().getName(X500Principal.RFC2253));
    }


    private void checkName(X500Principal actual, String claimed) throws IOException {
        if (claimed != null &&
                !actual.getName(X500Principal.RFC2253).equals(CertificateUtil.convertLegacyToRFC2253(claimed))) {
            badCertMatch();
        }
    }

    void verify(XMLSignatureWrapper signature) throws IOException, GeneralSecurityException {
        // Right kind of XML Dsig?
        if (signature.certificates == null) {
            throw new IOException("Missing X.509 certificates!");
        }
        // Get certificates
        certpath = signature.certificates;

        // Check signature
        core_verify(signature, certpath[0].getPublicKey());

        // If any signature cert specifiers have been given they must match
        checkName(certpath[0].getSubjectX500Principal(), signature.x509SubjectName);
        checkName(certpath[0].getIssuerX500Principal(), signature.x509IssuerName);
        if ((signature.x509IssuerName != null &&
                !certpath[0].getSerialNumber().equals(signature.x509SerialNumber))) {
            badCertMatch();
        }

        // Check trust path
        verifier_interface.verifyCertificatePath(certpath);
    }


    /**
     * Creates an XMLVerifier using the given verifier object
     *
     * @param verifier {@link VerifierInterface VerifierInterface} containing the
     *                 certificates and method needed.
     */
    public XMLVerifier(VerifierInterface verifier) {
        this.verifier_interface = verifier;
    }

}
