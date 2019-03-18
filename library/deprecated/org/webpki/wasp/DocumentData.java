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

import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import static org.webpki.wasp.WASPConstants.*;

/**
 * Implements the WASP "DocumentData" XML object
 */
public class DocumentData extends XMLObjectWrapper {

    private String prefix;  // Default: no prefix

    Node root;

    Vector<RootDocument> documents = new Vector<RootDocument>();

    public static final String DOCUMENT_DATA_ELEM = "DocumentData";

    private class NodeManipulator {
        NodeList nodelist;
        int index;

        NodeManipulator(Node parent) throws IOException {
            nodelist = parent.getChildNodes();
        }

        Element get() throws IOException {
            while (index < nodelist.getLength()) {
                Node node = nodelist.item(index++);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    return (Element) node;
                }
            }
            throw new IOException("Missing element");
        }
    }


    public void init() throws IOException {
        addSchema(WASP_SCHEMA_FILE);
    }


    protected boolean hasQualifiedElements() {
        return true;
    }


    public String namespace() {
        return WASP_NS;
    }


    public String element() {
        return DOCUMENT_DATA_ELEM;
    }


    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }


    public RootDocument replaceDocument(RootDocument doc) throws IOException {
        RootDocument orig = getDocument(doc.content_id);
        if (root == null) {
            throw new IOException("DocumentData has not be read from XML!");
        }
        DocumentData new_dd = new DocumentData();
        new_dd.prefix = root.getPrefix();
        new_dd.addDocument(doc);
        Element elem = new NodeManipulator(new_dd.getRootElement()).get();
        String content_id = elem.getAttribute(CONTENT_ID_ATTR);
        NodeManipulator orig_nl = new NodeManipulator(root);
        for (; ; ) {
            Element curr = orig_nl.get();
            if (content_id.equals(curr.getAttribute(CONTENT_ID_ATTR))) {
                root.replaceChild(root.getOwnerDocument().importNode(elem, true), curr);
                return documents.set(documents.indexOf(orig), doc);
            }
        }
    }


    public RootDocument[] getDocuments() {
        return documents.toArray(new RootDocument[0]);
    }


    public void addDocument(RootDocument doc) {
        documents.add(doc);
    }


    public RootDocument getDocument(String content_id) throws IOException {
        for (RootDocument doc : documents) {
            if (content_id.equals(doc.content_id)) {
                return doc;
            }
        }
        throw new IOException("Document \"" + content_id + "\" missing");
    }


    private void readDocuments(DOMReaderHelper rd) throws IOException {
        rd.getChild();
        do {
            addDocument(RootDocument.read(rd));
        }
        while (rd.hasNext());
        rd.getParent();
    }


    protected void fromXML(DOMReaderHelper rd) throws IOException {
        root = rd.current();
        readDocuments(rd);
    }


    static DocumentData read(DOMReaderHelper rd) throws IOException {
        DocumentData doc_data = new DocumentData();
        doc_data.root = rd.getNext(DOCUMENT_DATA_ELEM);
        doc_data.readDocuments(rd);
        return doc_data;
    }


    private void writeDocuments(DOMWriterHelper wr) throws IOException {
        for (RootDocument doc : documents) {
            doc.write(wr);
        }
    }


    public void write(DOMWriterHelper wr) throws IOException {
        wr.addChildElement(DOCUMENT_DATA_ELEM);
        writeDocuments(wr);
        wr.getParent();
    }


    void write(DOMWriterHelper wr, Element sorter) throws IOException {
        wr.addChildElement(DOCUMENT_DATA_ELEM);
        NodeManipulator ref_list = new NodeManipulator(sorter);
        int i = documents.size();
        while (i-- > 0) {
            getDocument(ref_list.get().getAttribute(CONTENT_ID_ATTR)).write(wr);
        }
        wr.getParent();
    }


    protected void toXML(DOMWriterHelper wr) throws IOException {
        wr.initializeRootObject(prefix);
        writeDocuments(wr);
    }


    public boolean equals(DocumentData dd) throws IOException {
        int i = documents.size();
        if (dd.documents.size() != i) {
            return false;
        }
        while (--i >= 0) {
            RootDocument the_doc = dd.documents.elementAt(i);
            if (!the_doc.equals(getDocument(the_doc.content_id))) {
                return false;
            }
        }
        return true;
    }

}
