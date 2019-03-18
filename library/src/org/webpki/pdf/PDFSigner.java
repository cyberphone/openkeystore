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
import java.util.Vector;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;

import com.lowagie.text.Rectangle;
import com.lowagie.text.DocumentException;

import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfSigGenericPKCS;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfLiteral;
import com.lowagie.text.pdf.PdfString;


public class PDFSigner {

    private SignerInterface signer;

    private String reason;

    private String location;

    private boolean enable_signature_graphics;

    private class Attachment {
        String filename;
        String description;
        byte[] data;
    }

    private Vector<Attachment> attachments = new Vector<Attachment>();


    public PDFSigner(SignerInterface signer) {
        this.signer = signer;
    }


    public void setSignatureGraphics(boolean flag) {
        enable_signature_graphics = flag;
    }


    public void setReason(String reason) {
        this.reason = reason;
    }


    public void setLocation(String location) {
        this.location = location;
    }


    public void addAttachment(String filename, String description, byte[] data) {
        Attachment file = new Attachment();
        file.filename = filename;
        file.description = description;
        file.data = data;
        attachments.add(file);
    }


    public byte[] addDocumentSignature(byte[] indoc, boolean certified) throws IOException {
        try {
            PdfReader reader = new PdfReader(indoc);
            ByteArrayOutputStream bout = new ByteArrayOutputStream(8192);
            PdfStamper stp = PdfStamper.createSignature(reader, bout, '\0', null, true);

            for (Attachment file : attachments) {
                stp.addFileAttachment(file.description, file.data, "dummy", file.filename);
            }

            PdfSignatureAppearance sap = stp.getSignatureAppearance();
            sap.setCrypto(null, signer.getCertificatePath(), null, PdfSignatureAppearance.WINCER_SIGNED);

            if (reason != null) {
                sap.setReason(reason);
            }
            if (location != null) {
                sap.setLocation(location);
            }

            if (enable_signature_graphics) {
                sap.setVisibleSignature(new Rectangle(100, 100, 400, 130), reader.getNumberOfPages(), null);
            }

            sap.setCertified(certified);

            //           sap.setExternalDigest (new byte[128], new byte[20], "RSA");
            sap.setExternalDigest(new byte[512], new byte[20], "RSA");
            sap.preClose();
            MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
            byte buf[] = new byte[8192];
            int n;
            InputStream inp = sap.getRangeStream();
            while ((n = inp.read(buf)) > 0) {
                messageDigest.update(buf, 0, n);
            }
            byte hash[] = messageDigest.digest();
            PdfSigGenericPKCS sg = sap.getSigStandard();
            PdfLiteral slit = (PdfLiteral) sg.get(PdfName.CONTENTS);
            byte[] outc = new byte[(slit.getPosLength() - 2) / 2];
            PdfPKCS7 sig = sg.getSigner();
            sig.setExternalDigest(signer.signData(hash, AsymSignatureAlgorithms.RSA_SHA1), hash, "RSA");
            PdfDictionary dic = new PdfDictionary();
            byte[] ssig = sig.getEncodedPKCS7();
            System.arraycopy(ssig, 0, outc, 0, ssig.length);
            dic.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
            sap.close(dic);

            return bout.toByteArray();
        } catch (NoSuchAlgorithmException nsae) {
            throw new IOException(nsae.getMessage());
        } catch (DocumentException de) {
            throw new IOException(de.getMessage());
        }
    }

}
