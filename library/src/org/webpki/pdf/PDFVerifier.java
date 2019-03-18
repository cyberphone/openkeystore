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
package org.webpki.pdf;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import java.util.ArrayList;
import java.util.Date;

import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateUtil;

import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;

public class PDFVerifier {

    private VerifierInterface verifier;

    private Date signing_time;

    private int document_revision;

    private boolean whole_doc_signature;

    private String signature_name;

    private boolean stop_on_index;

    private int stop_index;

    private boolean is_modified;

    private byte[] file_data;


    public PDFVerifier(VerifierInterface verifier) {
        this.verifier = verifier;
    }


    public Date getSigningTime() {
        return signing_time;
    }


    public int getDocumentRevision() {
        return document_revision;
    }


    public boolean getSignatureCoversWholeDocument() {
        return whole_doc_signature;
    }


    public String getSignatureName() {
        return signature_name;
    }


    public boolean getDocumentModifiedStatus() {
        return is_modified;
    }


    public void selectSignatureByIndex(int index) {
        stop_on_index = true;
        stop_index = index;
    }


    public byte[] getUnsignedDocument() {
        return file_data;
    }


    public void verifyDocumentSignature(byte[] indoc) throws IOException {
        try {
            PdfReader reader = new PdfReader(indoc);
            AcroFields af = reader.getAcroFields();
            ArrayList<?> names = af.getSignatureNames();
            for (int k = 0; k < names.size(); ++k) {
                String name = (String) names.get(k);
                whole_doc_signature = af.signatureCoversWholeDocument(name);
                if ((stop_on_index && k == stop_index) || (!stop_on_index && whole_doc_signature)) {
                    signature_name = name;
                    document_revision = af.getRevision(name);
                    ByteArrayOutputStream bout = new ByteArrayOutputStream(8192);
                    byte buffer[] = new byte[8192];
                    InputStream ip = af.extractRevision(name);
                    int n = 0;
                    while ((n = ip.read(buffer)) > 0) {
                        bout.write(buffer, 0, n);
                    }
                    bout.close();
                    ip.close();
                    file_data = bout.toByteArray();
                    PdfPKCS7 pk = af.verifySignature(name);
                    signing_time = pk.getSignDate().getTime();
                    X509Certificate pkc[] = (X509Certificate[]) pk.getCertificates();
                    is_modified = !pk.verify();
                    X509Certificate cert = pk.getSigningCertificate();
                    for (int q = 0; q < pkc.length; q++) {
                        if (cert.equals(pkc[q])) {
                            verifier.verifyCertificatePath(CertificateUtil.getSortedPath(pkc));
                            return;
                        }
                    }
                    throw new IOException("Signature certificate not found in path");
                }
            }
            if (stop_on_index) {
                throw new IOException("Signature with index " + stop_index + " not found");
            }
            throw new IOException("No whole-document signature found");
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse.getMessage());
        }
    }

}
