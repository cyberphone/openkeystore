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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.w3c.dom.Element;

import org.webpki.util.DebugFormatter;
import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.crypto.HashAlgorithms;

import static org.webpki.wasp.WASPConstants.*;


public class DocumentSignatures {

    private static final String DOC_SIGN_ELEM = "DocumentSignatures";

    private static final String DIGEST_SUB_ELEM = "Digest";

    private HashAlgorithms digest_algorithm;

    private String canonicalization_algorithm;

    public class ContentIDAndDigest {
        private ContentIDAndDigest() {
        }

        private String content_id;

        private byte[] digest;

        public String getContentID() {
            return content_id;
        }

        public byte[] getDigest() {
            return digest;
        }
    }


    Vector<ContentIDAndDigest> signatures = new Vector<ContentIDAndDigest>();


    @SuppressWarnings("unused")
    private DocumentSignatures() {
    }


    private DocumentSignatures(HashAlgorithms digest_algorithm, String canonicalization_algorithm) throws IOException {
        if (canonicalization_algorithm == null) {
            canonicalization_algorithm = DOC_SIGN_CN_ALG;
        } else if (!canonicalization_algorithm.equals(DOC_SIGN_CN_ALG)) {
            throw new IOException("Unsupported canonicalization algorithm: " + canonicalization_algorithm);
        }
        if (digest_algorithm == null) {
            digest_algorithm = HashAlgorithms.SHA256;
        }
        this.digest_algorithm = digest_algorithm;
        this.canonicalization_algorithm = canonicalization_algorithm;
    }


    public DocumentSignatures(HashAlgorithms digest_algorithm, String canonicalization_algorithm, DocumentData doc_data) throws IOException {
        this(digest_algorithm, canonicalization_algorithm);
        for (RootDocument rd : doc_data.documents) {
            addContentIDAndHashData(rd.content_id, rd.data);
        }
    }


    DocumentSignatures(DocumentData doc_data) throws IOException {
        this(null, null, doc_data);
    }


    public Element write(DOMWriterHelper wr, boolean output_ns) throws IOException {
        Element elem = output_ns ?
                wr.addChildElementNS(WASP_NS, DOC_SIGN_ELEM) : wr.addChildElement(DOC_SIGN_ELEM);
        wr.setStringAttribute(DIGEST_ALG_ATTR, digest_algorithm.getAlgorithmId());
        wr.setStringAttribute(CN_ALG_ATTR, canonicalization_algorithm);
        for (ContentIDAndDigest t : signatures) {
            wr.addBinary(DIGEST_SUB_ELEM, t.digest);
            wr.setStringAttribute(CONTENT_ID_ATTR, t.content_id);
        }
        wr.getParent();
        return elem;
    }

    public Element write(DOMWriterHelper wr) throws IOException {
        return write(wr, false);
    }


    public byte[] getDigest(String content_id) throws IOException {
        for (ContentIDAndDigest t : signatures) {
            if (content_id.equals(t.content_id)) return t.digest;
        }
        throw new IOException("No such ContentID: " + content_id);
    }


    public ContentIDAndDigest[] getAllContentIDAndDigests() {
        return signatures.toArray(new ContentIDAndDigest[0]);
    }


    private void add(String content_id, byte[] digest) throws IOException {
        ContentIDAndDigest cad = new ContentIDAndDigest();
        cad.content_id = content_id;
        cad.digest = digest;
        for (ContentIDAndDigest t : signatures) {
            if (cad.equals(t.content_id)) {
                throw new IOException("Multiply defined ContentID: " + content_id);
            }
        }
        signatures.add(cad);
    }


    public void addContentIDAndHashData(String content_id, byte[] data) throws IOException {
        try {
            add(content_id, MessageDigest.getInstance(digest_algorithm.getJCEName()).digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e.toString());
        }
    }


    public static DocumentSignatures read(DOMReaderHelper rd) throws IOException {
        rd.getNext(DOC_SIGN_ELEM);
        DOMAttributeReaderHelper ah = rd.getAttributeHelper();
        DocumentSignatures ds =
                new DocumentSignatures(HashAlgorithms.getAlgorithmFromID(ah.getString(DIGEST_ALG_ATTR)),
                        ah.getString(CN_ALG_ATTR));
        rd.getChild();
        while (rd.hasNext()) {
            byte[] digest = rd.getBinary(DIGEST_SUB_ELEM);
            ds.add(ah.getString(CONTENT_ID_ATTR), digest);
        }
        rd.getParent();
        return ds;
    }


    public boolean equals(DocumentSignatures ds) throws IOException {
        if (signatures.size() != ds.signatures.size() ||
                !canonicalization_algorithm.equals(ds.canonicalization_algorithm) ||
                digest_algorithm != ds.digest_algorithm) {
            return false;
        }
        for (ContentIDAndDigest t : signatures) {
            if (!ArrayUtil.compare(t.digest, ds.getDigest(t.content_id))) {
                throw new IOException("Mismatch on hash for '" + t.content_id + "'");
            }
        }
        return true;
    }


    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append(DIGEST_ALG_ATTR + "=" + digest_algorithm.getAlgorithmId() +
                "\n" + CN_ALG_ATTR + "=" + canonicalization_algorithm);
        for (ContentIDAndDigest t : signatures) {
            s.append("\n" + t.content_id + "=" + DebugFormatter.getHexString(t.digest));
        }
        return s.toString();
    }

}
