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

import java.util.Vector;

import org.w3c.dom.Element;

import org.webpki.util.MIMETypedObject;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyContainerTypes;
import org.webpki.crypto.KeyUsageBits;

import static org.webpki.wasp.WASPConstants.*;


public class SignatureRequestDecoder extends SignatureRequest {

    private Vector<SignatureProfileDecoder> sign_profiles = new Vector<SignatureProfileDecoder>();

    private Vector<CertificateFilter> cert_filters = new Vector<CertificateFilter>();  // Optional

    private DocumentReferences doc_refs;

    private DocumentData doc_data;

    private String id;

    private String serverTime;

    private String submitUrl;

    private String cancel_url;                                                          // Optional

    private ClientPlatformFeature client_platform_request;                              // Optional

    private String signature_gui_policy;                                                // Optional

    private String[] languages;                                                         // Optional

    private boolean copy_data;                                                          // Default: false

    private int expires;                                                                // Optional

    private XMLSignatureWrapper signature;                                              // Optional

    private Attachment[] attachment_list;

    private EmbeddedObject[] embedded_object_list;


    static CertificateFilter readCertificateFilter(DOMReaderHelper rd) throws IOException {
        rd.getNext(CERTIFICATE_FILTER_ELEM);
        DOMAttributeReaderHelper ah = rd.getAttributeHelper();
        CertificateFilter cf = new CertificateFilter();
        cf.setFingerPrint(ah.getBinaryConditional(CF_SHA1_ATTR));
        cf.setIssuerRegEx(ah.getStringConditional(CF_ISSUER_ATTR));
        cf.setSubjectRegEx(ah.getStringConditional(CF_SUBJECT_ATTR));
        cf.setEmailRegEx(ah.getStringConditional(CF_EMAIL_ATTR));
        cf.setSerialNumber(ah.getBigIntegerConditional(CF_SERIAL_ATTR));
        cf.setPolicyRules(ah.getListConditional(CF_POLICY_ATTR));
        String[] scontainers = ah.getListConditional(CF_CONTAINERS_ATTR);
  /*
        KeyContainerTypes[] containers = null;
        if (scontainers != null)
          {
            containers = new KeyContainerTypes[scontainers.length];
            for (int q = 0; q < scontainers.length; q++)
              {
                boolean found = false;
                for (int i = 0; i < NAME2KEYCONTAINER.length; i++)
                  {
                    if (NAME2KEYCONTAINER[i].equals (scontainers[q]))
                      {
                        found = true;
                        containers[q] = KEYCONTAINER2NAME[i];
                        break;
                      }
                  }
                if (!found) throw new IOException ("Unknown container: " + scontainers[q]);
              }
          }
        cf.setContainers (containers);
*/
        cf.setKeyUsageRules(ah.getListConditional(CF_KEY_USAGE_ATTR));
        cf.setExtendedKeyUsageRules(ah.getListConditional(CF_EXT_KEY_USAGE_ATTR));
        return cf;
    }


    public class BaseDocument implements MIMETypedObject {
        Object user_object;

        boolean referenced;
        byte[] data;
        String content_id;
        String mimeType;
        String meta_data;

        BaseDocument(DocumentReferences.Reference ref) throws IOException {
            if ((data = doc_data.getDocument(ref.content_id).data) == null) {
                if (doc_data.getDocument(ref.content_id) instanceof InternalDocument) {
                    throw new IOException("You MUST NOT use \"Internal\" data in a SignatureRequest");
                }
                if (doc_data.getDocument(ref.content_id) instanceof DeletedDocument) {
                    throw new IOException("You MUST NOT use \"Deleted\" data in a SignatureRequest");
                }
            }
            content_id = ref.content_id;
            mimeType = ref.mimeType;
            meta_data = ref.meta_data;
        }

        public String getContentID() {
            return content_id;
        }

        public byte[] getData() {
            referenced = true;
            return data;
        }

        public String getMimeType() {
            return mimeType;
        }

        public String getMetaData() {
            return meta_data;
        }

        public boolean isReferenced() {
            return referenced;
        }

        public Object getUserObject() {
            return user_object;
        }

        public Object setUserObject(Object user_object) {
            return this.user_object = user_object;
        }

    }


    public class Attachment extends BaseDocument {
        boolean provider_originated;
        String description;
        String file;
        boolean must_access;

        Attachment(DocumentReferences.Reference ref) throws IOException {
            super(ref);
            provider_originated = ref.provider_originated;
            description = ref.description;
            file = ref.file;
            must_access = ref.must_access;
        }

        public boolean getProviderOriginated() {
            return provider_originated;
        }

        public String getDescription() {
            return description;
        }

        public String getFile() {
            return file;
        }

        public boolean getMustAccess() {
            return must_access;
        }

    }


    public class EmbeddedObject extends BaseDocument {
        EmbeddedObject(DocumentReferences.Reference ref) throws IOException {
            super(ref);
        }
    }


    public class Document extends BaseDocument {
        Document(DocumentReferences.Reference ref) throws IOException {
            super(ref);
        }
    }


    public SignatureProfileDecoder[] getSignatureProfilesDecoders() {
        return sign_profiles.toArray(new SignatureProfileDecoder[0]);
    }


    public CertificateFilter[] getCertificateFilters() {
        return cert_filters.toArray(new CertificateFilter[0]);
    }


    public Attachment[] getAttachments() throws IOException {
        if (attachment_list == null) {
            DocumentReferences.Reference[] ref_list = doc_refs.getAttachmentReferences();
            attachment_list = new Attachment[ref_list.length];
            for (int i = 0; i < ref_list.length; i++) {
                attachment_list[i] = new Attachment(ref_list[i]);
            }
        }
        return attachment_list;
    }


    public EmbeddedObject[] getEmbeddedObjects() throws IOException {
        if (embedded_object_list == null) {
            DocumentReferences.Reference[] ref_list = doc_refs.getEmbeddedObjectReferences();
            embedded_object_list = new EmbeddedObject[ref_list.length];
            for (int i = 0; i < ref_list.length; i++) {
                embedded_object_list[i] = new EmbeddedObject(ref_list[i]);
            }
        }
        return embedded_object_list;
    }


    public EmbeddedObject getEmbeddedObject(String content_id) throws IOException {
        return new EmbeddedObject(doc_refs.getReference(content_id));
    }


    private Document optDoc(DocumentReferences.Reference ref) throws IOException {
        return ref == null ? null : new Document(ref);
    }


    public Document getMainDocument() throws IOException {
        return optDoc(doc_refs.getMainDocument());
    }


    public Document getProcessingDocument() throws IOException {
        return optDoc(doc_refs.getProcessingDocument());
    }


    public Document getDetailDocument() throws IOException {
        return optDoc(doc_refs.getDetailDocument());
    }


    public DocumentData getDocumentData() {
        return doc_data;
    }


    public DocumentReferences getDocumentReferences() {
        return doc_refs;
    }


    public String getID() {
        return id;
    }


    public String getServerTime() {
        return serverTime;
    }


    public String getSubmitUrl() {
        return submitUrl;
    }


    public String getCancelURL() {
        return cancel_url;
    }


    public ClientPlatformFeature getClientPlatformRequest() {
        return client_platform_request;
    }


    public String getSignatureGUIPolicy() {
        return signature_gui_policy;
    }


    public String[] getLanguages() {
        return languages;
    }


    public boolean getCopyData() {
        return copy_data;
    }


    public int getExpires() {
        return expires;
    }


    public DocumentSignatures getDocumentSignatures(HashAlgorithms digestAlgorithm,
                                                    String canonicalizationAlgorithm) throws IOException {
        return new DocumentSignatures(digestAlgorithm, canonicalizationAlgorithm, doc_data);
    }


    public void verifySignature(VerifierInterface verifier) throws IOException {
        new XMLVerifier(verifier).validateEnvelopedSignature(this, null, signature, id);
    }


    public boolean isSigned() {
        return signature != null;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML(DOMReaderHelper rd) throws IOException {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        id = ah.getString(ID_ATTR);

        serverTime = ah.getString(SERVER_TIME_ATTR);  // No point in converting to local presentation

        submitUrl = ah.getString(SUBMIT_URL_ATTR);

        cancel_url = ah.getStringConditional(ABORT_URL_ATTR);

        signature_gui_policy = ah.getStringConditional(SIGNATURE_GUI_POLICY_ATTR);

        languages = ah.getListConditional(LANGUAGES_ATTR);

        copy_data = ah.getBooleanConditional(COPY_DATA_ATTR);

        expires = ah.getIntConditional(EXPIRES_ATTR, -1);  // Default: no timeout and associated GUI

        rd.getChild();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature profiles [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext(SIGNATURE_PROFILES_ELEM);
        rd.getChild();
        do {
            Element data = rd.getNext();
            if (hasWrapper(data)) // We may NOT know the namespace (lax processing)
            {
                XMLObjectWrapper wrappedData = wrap(data);
                if (wrappedData instanceof SignatureProfileDecoder) {
                    if (((SignatureProfileDecoder) wrappedData).hasSupportedParameters()) {
                        sign_profiles.add((SignatureProfileDecoder) wrappedData);
                    }
                } else {
                    throw new IOException("SignatureProfileDecoder instance expected but we got:" + wrappedData);
                }
            }
        }
        while (rd.hasNext());
        rd.getParent();
        if (sign_profiles.isEmpty()) {
            throw new IOException("No known signature profiles found!");
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the certificate filters [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext(CERTIFICATE_FILTER_ELEM)) {
            cert_filters.add(readCertificateFilter(rd));
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the document references [1]
        /////////////////////////////////////////////////////////////////////////////////////////
        doc_refs = DocumentReferences.read(rd);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the document data [1]
        /////////////////////////////////////////////////////////////////////////////////////////
        doc_data = DocumentData.read(rd);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional client platform request data [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext(ClientPlatformFeature.CLIENT_PLATFORM_FEATURE_ELEM)) {
            client_platform_request = ClientPlatformFeature.read(rd);
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the signature [0..1]
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext(XMLSignatureWrapper.SIGNATURE_ELEM)) {
            signature = (XMLSignatureWrapper) wrap(rd.getNext());
        }
    }

}
