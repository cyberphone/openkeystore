/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.pdf;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.util.TimeZone;

import java.text.SimpleDateFormat;

import org.webpki.util.IO;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.KeyStoreVerifier;

public class Verify {

    public static void main(String argv[]) throws IOException, GeneralSecurityException {
        if (argv.length != 2 && argv.length != 1) {
            System.out.println("PDFVerifier [n] infile\n\n      n = index of selected signature\n" +
                    "  (default is the whole-document signature)");
            System.exit(3);
        }
        KeyStoreVerifier verifier = new KeyStoreVerifier(DemoKeyStore.getCAKeyStore());
        verifier.setTrustedRequired(false);
        PDFVerifier pdf_verifier = new PDFVerifier(verifier);
        if (argv.length == 2) {
            pdf_verifier.selectSignatureByIndex(Integer.parseInt(argv[0]));
        }
        pdf_verifier.verifyDocumentSignature(IO.readFile(argv[argv.length - 1]));
        System.out.println("Signature name: " + pdf_verifier.getSignatureName());
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss z");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        System.out.println("Signature time: " + sdf.format(pdf_verifier.getSigningTime()));
        System.out.println("Signature covers whole document: " + pdf_verifier.getSignatureCoversWholeDocument());
        System.out.println("Document revision: " + pdf_verifier.getDocumentRevision());
        System.out.println("Document modified: " + pdf_verifier.getDocumentModifiedStatus());
        System.out.println("Signer certificate:\n" + new CertificateInfo(verifier.getSignerCertificate()).toString());
        IO.writeFile("c:\\unsigned-file.pdf", pdf_verifier.getUnsignedDocument());
    }

}
