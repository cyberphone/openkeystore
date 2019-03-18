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
import java.util.Hashtable;

import org.w3c.dom.Element;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import static org.webpki.wasp.WASPConstants.*;

// Implements the WASP "DocumentReferences" XML fragment


public class DocumentReferences {

    Reference main_document;

    Reference detail_document;

    Reference processing_document;

    Vector<Reference> embedded_objects = new Vector<Reference>();

    Vector<Reference> attachments = new Vector<Reference>();

    private Hashtable<String, Reference> all_elements = new Hashtable<String, Reference>();

    public static final String DOC_REF_ELEM = "DocumentReferences";

    private static final String DETAIL_DOCUMENT_SUB_ELEM = "DetailDocument";

    private static final String PROCESSING_DOCUMENT_SUB_ELEM = "ProcessingDocument";

    private static final String ATTACHMENT_SUB_ELEM = "Attachment";

    private static final String META_DATA_ATTR = "MetaData";

    private static final String PROVIDER_ORIGINATED_ATTR = "ProviderOriginated";

    private static final String DESCRIPTION_ATTR = "Description";

    private static final String FILE_ATTR = "File";

    private static final String MUSTACCESS_ATTR = "MustAccess";


    public class Reference {
        // Always applicable attributes
        String content_id;
        String mimeType;
        String meta_data;  // Optional

        // Attachment additions. Not 100% OO, but what the heck!
        boolean provider_originated;  // Optional
        String description;
        String file;
        boolean must_access;          // Optional

        private Reference() {
        }
    }


    public Reference getReference(String content_id) throws IOException {
        Reference ref = all_elements.get(content_id);
        if (ref == null) {
            throw new IOException("Document \"" + content_id + "\" missing");
        }
        return ref;
    }


    public Reference getMainDocument() {
        return main_document;
    }


    public Reference getDetailDocument() {
        return detail_document;
    }


    public Reference getProcessingDocument() {
        return processing_document;
    }


    private void writeReference(String element, Reference ref, DOMWriterHelper wr) throws IOException {
        wr.addChildElement(element);
        wr.setStringAttribute(CONTENT_ID_ATTR, ref.content_id);
        wr.setStringAttribute(MIME_TYPE_ATTR, ref.mimeType);
        if (ref.meta_data != null) {
            wr.setStringAttribute(META_DATA_ATTR, ref.meta_data);
        }
        if (ref.provider_originated) {
            wr.setBooleanAttribute(PROVIDER_ORIGINATED_ATTR, true);
        }
        if (ref.description != null) {
            wr.setStringAttribute(DESCRIPTION_ATTR, ref.description);
        }
        if (ref.file != null) {
            wr.setStringAttribute(FILE_ATTR, ref.file);
        }
        if (ref.must_access) {
            wr.setBooleanAttribute(MUSTACCESS_ATTR, true);
        }
        wr.getParent();
    }


    public Element write(DOMWriterHelper wr, boolean output_ns) throws IOException {
        Element elem = output_ns ? wr.addChildElementNS(WASP_NS, DOC_REF_ELEM) : wr.addChildElement(DOC_REF_ELEM);
        if (main_document == null) {
            throw new IOException(MAIN_DOCUMENT_SUB_ELEM + " is missing!");
        }
        writeReference(MAIN_DOCUMENT_SUB_ELEM, main_document, wr);
        if (detail_document != null) {
            writeReference(DETAIL_DOCUMENT_SUB_ELEM, detail_document, wr);
        }
        if (processing_document != null) {
            writeReference(PROCESSING_DOCUMENT_SUB_ELEM, processing_document, wr);
        }
        for (Reference ref : embedded_objects) {
            writeReference(EMBEDDED_OBJECT_SUB_ELEM, ref, wr);
        }
        for (Reference ref : attachments) {
            writeReference(ATTACHMENT_SUB_ELEM, ref, wr);
        }
        wr.getParent();
        return elem;
    }


    public Element write(DOMWriterHelper wr) throws IOException {
        return write(wr, false);
    }


    Reference addReference(String content_id, String mimeType, String meta_data) {
        return addReference(content_id, mimeType, meta_data, false, null, null, false);
    }


    private Reference addReference(String content_id, String mimeType, String meta_data,
                                   boolean provider_originated, String description, String file, boolean must_access) {
        Reference ref = new Reference();
        ref.content_id = content_id;
        ref.mimeType = mimeType;
        ref.meta_data = meta_data;
        ref.provider_originated = provider_originated;
        ref.description = description;
        ref.file = file;
        ref.must_access = must_access;
        all_elements.put(content_id, ref);
        return ref;
    }


    Reference addAttachmentReference(String content_id, String mimeType, String meta_data,
                                     boolean provider_originated, String description, String file, boolean must_access) {
        Reference ref = addReference(content_id, mimeType, meta_data, provider_originated, description, file, must_access);
        attachments.add(ref);
        return ref;
    }


    Reference addEmbeddedObjectReference(String content_id, String mimeType, String meta_data) {
        Reference ref = addReference(content_id, mimeType, meta_data);
        embedded_objects.add(ref);
        return ref;
    }


    Reference[] getAttachmentReferences() {
        return attachments.toArray(new Reference[0]);
    }


    Reference[] getEmbeddedObjectReferences() {
        return embedded_objects.toArray(new Reference[0]);
    }


    private Reference readReference(boolean attachment, DOMReaderHelper rd) throws IOException {
        rd.getNext();
        DOMAttributeReaderHelper ah = rd.getAttributeHelper();
        String content_id = ah.getString(CONTENT_ID_ATTR);
        String mimeType = ah.getString(MIME_TYPE_ATTR);
        String meta_data = ah.getStringConditional(META_DATA_ATTR);
        if (attachment) {
            boolean provider_originated = ah.getBooleanConditional(PROVIDER_ORIGINATED_ATTR);
            String description = ah.getString(DESCRIPTION_ATTR);
            String file = ah.getString(FILE_ATTR);
            boolean must_access = ah.getBooleanConditional(MUSTACCESS_ATTR);
            return addReference(content_id, mimeType, meta_data, provider_originated, description, file, must_access);
        }
        return addReference(content_id, mimeType, meta_data, false, null, null, false);
    }


    private void readMultiple(String name, Vector<Reference> container, boolean attachment, DOMReaderHelper rd) throws IOException {
        while (rd.hasNext(name)) {
            container.add(readReference(attachment, rd));
        }
    }


    private Reference readReference(String name, boolean optional, DOMReaderHelper rd) throws IOException {
        if (rd.hasNext(name)) {
            return readReference(false, rd);
        } else if (optional) {
            return null;
        } else {
            throw new IOException("Missing \"" + name + "\" reference");
        }
    }


    public static DocumentReferences read(DOMReaderHelper rd) throws IOException {
        rd.getNext(DOC_REF_ELEM);
        DocumentReferences dr = new DocumentReferences();
        rd.getChild();
        dr.main_document = dr.readReference(MAIN_DOCUMENT_SUB_ELEM, false, rd);
        dr.detail_document = dr.readReference(DETAIL_DOCUMENT_SUB_ELEM, true, rd);
        dr.processing_document = dr.readReference(PROCESSING_DOCUMENT_SUB_ELEM, true, rd);
        dr.readMultiple(EMBEDDED_OBJECT_SUB_ELEM, dr.embedded_objects, false, rd);
        dr.readMultiple(ATTACHMENT_SUB_ELEM, dr.attachments, true, rd);
        if (rd.hasNext()) {
            throw new IOException("Unexpected \"" + DOC_REF_ELEM + "\" elements");
        }
        rd.getParent();
        return dr;
    }


    private boolean compare(String arg1, String arg2) {
        if (arg1 == null) {
            return arg2 == null;
        }
        return arg2 != null && arg1.equals(arg2);
    }

    private boolean compare(Reference arg1, Reference arg2) {
        if (arg1 == null) {
            return arg2 == null;
        }
        return arg2 != null &&
                compare(arg1.content_id, arg2.content_id) &&
                compare(arg1.mimeType, arg2.mimeType) &&
                compare(arg1.meta_data, arg2.meta_data) &&
                arg1.provider_originated == arg2.provider_originated &&
                compare(arg1.description, arg2.description) &&
                compare(arg1.file, arg2.file) &&
                arg1.must_access == arg2.must_access;

    }

    private boolean compare(Vector<Reference> arg1, Vector<Reference> arg2) {
        int i = arg1.size();
        if (arg2.size() != i) {
            return false;
        }
        while (--i >= 0) {
            if (!compare(arg1.elementAt(i), arg2.elementAt(i))) {
                return false;
            }
        }
        return true;
    }


    public void check(DocumentReferences dr) throws IOException {
        if (!(compare(main_document, dr.main_document) &&
                compare(detail_document, dr.detail_document) &&
                compare(processing_document, dr.processing_document) &&
                compare(embedded_objects, dr.embedded_objects) &&
                compare(attachments, dr.attachments))) {
            throw new IOException("Mismatch in DocumentReferences");
        }
    }

}
