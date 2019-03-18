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
package org.webpki.wasp.prof.xds;

import java.io.IOException;

import java.util.GregorianCalendar;
import java.util.Vector;

import java.security.cert.X509Certificate;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.util.ArrayUtil;

import org.webpki.wasp.DocumentSignatures;
import org.webpki.wasp.DocumentReferences;
import org.webpki.wasp.DocumentData;
import org.webpki.wasp.SignatureProfileResponseDecoder;
import org.webpki.wasp.SignatureProfileEncoder;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.SignedKeyInfoSpecifier;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateFilter;

import static org.webpki.wasp.WASPConstants.*;
import static org.webpki.wasp.prof.xds.XDSProfileConstants.*;


public class XDSProfileResponseDecoder extends XMLObjectWrapper implements SignatureProfileResponseDecoder {

    // Attributes
    private String id;

    private String submitUrl;

    private String requestUrl;

    private GregorianCalendar clientTime;

    private GregorianCalendar serverTime;

    private byte[] server_certificate_fingerprint;              // Optional

    private String[] unreferenced_attachments;                  // Optional

    // Elements
    private DocumentReferences doc_refs;

    private DocumentSignatures doc_signs;

    private XMLSignatureWrapper signature;

    private XMLVerifier ds;

    private X509Certificate[] signer_certpath;


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


    public String[] getUnreferencedAttachments() {
        return unreferenced_attachments;
    }


    public byte[] getServerCertificateFingerprint() {
        return server_certificate_fingerprint;
    }


    public String getRequestURL() {
        return requestUrl;
    }


    public String getSubmitUrl() {
        return submitUrl;
    }


    public GregorianCalendar getServerTime() {
        return serverTime;
    }


    public GregorianCalendar getClientTime() {
        return clientTime;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML(DOMReaderHelper rd) throws IOException {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes
        //////////////////////////////////////////////////////////////////////////
        id = ah.getString(ID_ATTR);

        serverTime = ah.getDateTime(SERVER_TIME_ATTR);

        submitUrl = ah.getString(SUBMIT_URL_ATTR);

        requestUrl = ah.getString(REQUEST_URL_ATTR);

        clientTime = ah.getDateTime(CLIENT_TIME_ATTR);

        server_certificate_fingerprint = ah.getBinaryConditional(SERVER_CERT_FP_ATTR);

        unreferenced_attachments = ah.getListConditional(UNREFERENCED_ATTACHMENTS_ATTR);

        rd.getChild();

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        doc_refs = DocumentReferences.read(rd);

        doc_signs = DocumentSignatures.read(rd);

        signature = (XMLSignatureWrapper) wrap(rd.getNext());
    }

    protected void toXML(DOMWriterHelper helper) throws IOException {
        throw new IOException("Should NEVER be called");
    }

    public void verifySignature(VerifierInterface verifier) throws IOException {
        ds = new XMLVerifier(verifier);
        ds.setSignedKeyInfo(SignedKeyInfoSpecifier.ALLOW_SIGNED_KEY_INFO);
        ds.validateEnvelopedSignature(this, null, signature, id);
        signer_certpath = verifier.getSignerCertificatePath();
    }


    private void bad(String what) throws IOException {
        throw new IOException(what);
    }


    public boolean match(SignatureProfileEncoder spreenc,
                         DocumentData doc_data,
                         DocumentReferences doc_refs,
                         Vector<CertificateFilter> cert_filters,
                         String id,
                         byte[] expected_fingerprint)
            throws IOException {
        // Is this the same profile?
        if (!(spreenc instanceof XDSProfileRequestEncoder)) {
            return false;
        }

        // Yes, it was!
        XDSProfileRequestEncoder enc = (XDSProfileRequestEncoder) spreenc;

        // Check that the ID attribute is OK
        if (!this.id.equals(id)) {
            bad("Non-matching ID attribute");
        }

        // Check that the document references are OK
        this.doc_refs.check(doc_refs);

        // Check that the document hashes are OK
        if (!(new DocumentSignatures(enc.digest_algorithm, enc.document_canonicalization_algorithm, doc_data).equals(doc_signs))) {
            return false;
        }

        if (enc.digest_algorithm != null && enc.digest_algorithm != ds.getDigestAlgorithm()) {
            bad("Wrong digest algorithm.  Requested: " + enc.digest_algorithm.getAlgorithmId() +
                    ".  Got: " + ds.getDigestAlgorithm().getAlgorithmId());
        }

        if (enc.signatureAlgorithm != null && enc.signatureAlgorithm != ds.getSignatureAlgorithm()) {
            bad("Wrong signature algorithm.  Requested: " + enc.signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.SKS) +
                    ".  Got: " + ds.getSignatureAlgorithm().getAlgorithmId(AlgorithmPreferences.SKS));
        }

        if (expected_fingerprint != null &&
                (server_certificate_fingerprint == null || !ArrayUtil.compare(server_certificate_fingerprint, expected_fingerprint))) {
            bad("Server certificate fingerprint");
        }

        if (cert_filters.size() > 0 && signer_certpath != null) {
            for (CertificateFilter cf : cert_filters) {
                if (cf.matches(signer_certpath)) {
                    return true;
                }
            }
            bad("Certificates does not match filter(s)");
        }

        // Success!
        return true;
    }

}
