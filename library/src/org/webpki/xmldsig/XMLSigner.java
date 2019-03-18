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
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;


public class XMLSigner extends XMLSignerCore {

    private SignerInterface signer_implem;

    PublicKey populateKeys(XMLSignatureWrapper r) throws GeneralSecurityException, IOException {
        // Prepare all certificate data
        r.certificates = signer_implem.getCertificatePath();
        X509Certificate certificate = r.certificates[0];

        r.x509IssuerName = certificate.getIssuerX500Principal().getName(X500Principal.RFC2253);
        r.x509SerialNumber = certificate.getSerialNumber();
        // Note: only output as a comment and therefore NOT normalized (unreadable)
        r.x509SubjectName = CertificateUtil.convertRFC2253ToLegacy(certificate.getSubjectX500Principal().getName());
        return certificate.getPublicKey();
    }

    byte[] getSignatureBlob(byte[] data, AsymSignatureAlgorithms sig_alg) throws GeneralSecurityException, IOException {
        return signer_implem.signData(data, sig_alg);
    }


    /**
     * Creates an XMLSigner using the given {@link SignerInterface SignerInterface}.
     *
     * @param signer Signer implementation
     */
    public XMLSigner(SignerInterface signer) {
        this.signer_implem = signer;
    }

}
