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
package org.webpki.wasp.prof.pdf;

import java.io.IOException;
import java.util.Date;

import org.w3c.dom.Text;

import org.webpki.util.Base64;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.wasp.DocumentSignatures;
import org.webpki.wasp.SignatureResponseEncoder;
import org.webpki.wasp.SignatureRequestDecoder;
import org.webpki.wasp.SignatureProfileResponseEncoder;

import org.webpki.pdf.PDFSigner;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignerInterface;

import static org.webpki.wasp.WASPConstants.*;
import static org.webpki.wasp.prof.pdf.PDFProfileConstants.*;

public class PDFProfileResponseEncoder extends XMLObjectWrapper implements SignatureProfileResponseEncoder {

    private String requestUrl;

    private Date clientTime;

    private String serverTime;

    private String id;

    private byte[] server_certificate_fingerprint;

    private Text pdf_object;

    private SignatureResponseEncoder s_resp_enc;

    private SignatureRequestDecoder s_req_dec;

    private DocumentSignatures doc_sign;

    PDFProfileRequestDecoder to_decoder;

    String prefix = "pr";  // Default: "pr:"


    protected boolean hasQualifiedElements() {
        return true;
    }


    public void init() throws IOException {
        addSchema(XML_SCHEMA_FILE);
    }


    public String namespace() {
        return XML_SCHEMA_NAMESPACE;
    }


    public String element() {
        return RESPONSE_ELEM;
    }


    PDFProfileResponseEncoder(PDFProfileRequestDecoder to_decoder) {
        this.to_decoder = to_decoder;
    }


    public PDFProfileResponseEncoder() {
    }


    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }


    protected void toXML(DOMWriterHelper wr) throws IOException {
        wr.initializeRootObject(prefix);
        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes (which is all this profile got...)
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute(ID_ATTR, id);

        wr.setStringAttribute(SUBMIT_URL_ATTR, s_req_dec.getSubmitUrl());
        wr.setStringAttribute(REQUEST_URL_ATTR, requestUrl);

        wr.setDateTimeAttribute(CLIENT_TIME_ATTR, clientTime);

        wr.setStringAttribute(SERVER_TIME_ATTR, serverTime);

        if (server_certificate_fingerprint != null) {
            wr.setBinaryAttribute(SERVER_CERT_FP_ATTR, server_certificate_fingerprint);
        }
        wr.pushPrefix(s_resp_enc.getPrefix());
        s_req_dec.getDocumentReferences().write(wr, true);
        doc_sign.write(wr, true);
        wr.popPrefix();
        pdf_object = wr.addString("SignedPDF", "DUMMY");
    }


    protected void fromXML(DOMReaderHelper helper) throws IOException {
        throw new IOException("Should NEVER be called");
    }


    public void createSignedData(SignerInterface signer,
                                 SignatureResponseEncoder s_resp_enc,
                                 SignatureRequestDecoder s_req_dec,
                                 String requestUrl,
                                 Date clientTime,
                                 byte[] server_certificate_fingerprint) throws IOException {
        this.s_resp_enc = s_resp_enc;
        this.s_req_dec = s_req_dec;
        this.requestUrl = requestUrl;
        this.clientTime = clientTime;
        serverTime = s_req_dec.getServerTime();
        id = s_req_dec.getID();
        this.server_certificate_fingerprint = server_certificate_fingerprint;
        doc_sign = new DocumentSignatures(HashAlgorithms.getAlgorithmFromID(to_decoder.digest_algorithm),
                to_decoder.document_canonicalization_algorithm,
                s_req_dec.getDocumentData());
        PDFSigner ds = new PDFSigner(signer);
        ds.setSignatureGraphics(true);
        forcedDOMRewrite();
        byte[] data = ds.addDocumentSignature(s_req_dec.getMainDocument().getData(), false);
        pdf_object.setNodeValue(new Base64(false).getBase64StringFromBinary(data));
    }

}
