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
package org.webpki.xml;

import java.io.IOException;
import java.io.Serializable;

import java.util.Arrays;

import org.w3c.dom.Element;
import org.w3c.dom.Document;

import org.webpki.xmldsig.XPathCanonicalizer;
import org.webpki.xmldsig.CanonicalizationAlgorithms;

public class XMLCookie implements Serializable {
    private static final long serialVersionUID = 1L;

    Element element;

    XMLCookie() {
    }

    public XMLCookie(Element element) {
        this.element = element;
    }

    public XMLCookie(Document d) {
        this(d.getDocumentElement());
    }


    public XMLCookie(XMLObjectWrapper wrapper) throws IOException {
        this(wrapper.toXMLDocument().document);
    }


    public byte[] getData() throws IOException {
        return DOMUtil.writeXML(element);
    }


    public byte[] getC14NData() throws IOException {
        return XPathCanonicalizer.serializeSubset(element, CanonicalizationAlgorithms.C14N_EXCL);
    }

    public boolean equals(XMLCookie ref) throws IOException {
        return Arrays.equals(getC14NData(), ref.getC14NData());
    }
}

