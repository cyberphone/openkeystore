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
package org.webpki.wasp;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.w3c.dom.Element;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMUtil;


public class SignatureResponseDecoder extends SignatureResponse {

    ////////////////////////////////////////////////////
    // Data coming from standard decoders
    ////////////////////////////////////////////////////
    private DocumentData doc_data;                                          // Optional (CopyData)

    private SignatureProfileResponseDecoder sign_prof_data;


    public DocumentData getDocumentData() {
        return doc_data;
    }


    public SignatureProfileResponseDecoder getSignatureProfileResponseDecoder() {
        return sign_prof_data;
    }


    private void bad(String what) throws IOException {
        throw new IOException(what);
    }


    public void checkRequestResponseIntegrity(SignatureRequestEncoder sreqenc, X509Certificate server_certificate) throws IOException {
        // The DocumentData object
        if (sreqenc.copy_data) {
            if (doc_data == null) bad("Missing DocumentData");
            if (!sreqenc.document_data.equals(doc_data)) bad("DocumentData mismatch");
        } else if (doc_data != null) bad("Unexpected DocumentData");
        byte[] expected_fingerprint = null;
        if (server_certificate != null) {
            try {
                expected_fingerprint = HashAlgorithms.SHA256.digest(server_certificate.getEncoded());
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }

        // For each candidate profile do a match try
        for (SignatureProfileEncoder spe : sreqenc.signature_profiles) {
            if (sign_prof_data.match(spe,
                    sreqenc.document_data,
                    sreqenc.document_references,
                    sreqenc.certificateFilters,
                    sreqenc.id,
                    expected_fingerprint)) {
                return;
            }
        }
        throw new IOException("Mismatch between signature request and response");
    }


    public void copyDocumentData(SignatureRequestEncoder sre) throws IOException {
        if (doc_data != null) {
            throw new IOException("DocumentData already present!");
        }
        Document owner = getRootDocument();
        Element root = getRootElement();
        sre.document_data.setPrefix(DOMUtil.getPrefix(root));
        sre.document_data.setNameSpaceMode(false);
        sre.document_data.forcedDOMRewrite();
        Node text = root.appendChild(owner.createTextNode("\n"));
        root.insertBefore(sre.document_data.root = owner.importNode(sre.document_data.getRootElement(), true), text);
        doc_data = sre.document_data;
    }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML(DOMReaderHelper rd) throws IOException {
        rd.getChild();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature profile response [1]
        /////////////////////////////////////////////////////////////////////////////////////////
        sign_prof_data = (SignatureProfileResponseDecoder) wrap(rd.getNext());

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional document data [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext(DocumentData.DOCUMENT_DATA_ELEM)) {
            doc_data = DocumentData.read(rd);
        }
    }

}
