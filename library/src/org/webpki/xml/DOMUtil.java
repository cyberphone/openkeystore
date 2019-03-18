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
package org.webpki.xml;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Node;
import org.w3c.dom.Element;
import org.w3c.dom.Document;

import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

/**
 * Utility methods for traversing and building DOM trees.
 */
public class DOMUtil {
    private static String class_document_builder_factory;

    /**
     * Private constructor, no reason to allow instatiation at this time.
     */
    private DOMUtil() {
    }

    /**
     * Forces the use of a specific implementation
     *
     * @param document_builder_factory Class name
     */
    public static void forceDocumentBuilderFactory(String document_builder_factory) {
        class_document_builder_factory = document_builder_factory;
    }

    /**
     * Creates a subelement with a single child, a text node, as a child of an existing node.
     * <p>The structure <code>&lt;<i>element</i>&gt;<i>value</i>&lt;/<i>element</i>&gt;</code>
     * will be created and appended to <i>parent</i>.
     *
     * @param parent  The parent of the new element.
     * @param element The name of the new element.
     * @param value   The value of the text node.
     * @return Element
     */
    public static Element appendTextElement(Element parent, String element, String value) {
        Document d = parent.getOwnerDocument();
        Element r = d.createElement(element);
        parent.appendChild(r);
        r.appendChild(d.createTextNode(value));

        return r;
    }

    /**
     * Creates a subelement with a single child, a text node, as a child of an existing node.
     * <p>The structure <code>&lt;<i>element</i>&gt;<i>value</i>&lt;/<i>element</i>&gt;</code>
     * will be created and appended to <i>parent</i>.
     * <p>This method is shorthand for
     * <code>{@link #appendTextElement(Element, String, String) appendTextElement}(parent, element, Integer.toString(value))</code>
     *
     * @param parent  The parent of the new element.
     * @param element The name of the new element.
     * @param value   The value of the text node.
     * @return Element
     * @see #appendTextElement(Element, String, String)
     */
    public static Element appendTextElement(Element parent, String element, int value) {
        return appendTextElement(parent, element, Integer.toString(value));
    }

    /**
     * Creates a subelement with a single child, a text node, as a child of an existing node.
     * <p>The structure <code>&lt;<i>element</i>&gt;<i>value</i>&lt;/<i>element</i>&gt;</code>
     * will be created and appended to <i>parent</i>.
     * <p>This method is shorthand for
     * <code>{@link #appendTextElement(Element, String, String) appendTextElement}(parent, element, Long.toString(value))</code>
     *
     * @param parent  The parent of the new element.
     * @param element The name of the new element.
     * @param value   The value of the text node.
     * @return Element
     * @see #appendTextElement(Element, String, String)
     */
    public static Element appendTextElement(Element parent, String element, long value) {
        return appendTextElement(parent, element, Long.toString(value));
    }

    /**
     * Creates a subelement with a single child, a text node, as a child of an existing node.
     * <p>The structure <code>&lt;<i>element</i>&gt;<i>value</i>&lt;/<i>element</i>&gt;</code>
     * will be created and appended to <i>parent</i>.
     * <p>This method is shorthand for
     * <code>{@link #appendTextElement(Element, String, String) appendTextElement}(parent, element, value.toString())</code>
     * and is hence useful when value is an object who's {@link Object#toString toString} function returns a suitably formatted
     * string representation, for example a {@link java.lang.StringBuilder StringBuilder},
     * {@link java.math.BigInteger BigInteger} or {@link java.math.BigDecimal BigDecimal}.
     *
     * @param parent  The parent of the new element.
     * @param element The name of the new element.
     * @param value   The value of the text node.
     * @return Element
     * @see #appendTextElement(Element, String, String)
     */
    public static Element appendTextElement(Element parent, String element, Object value) {
        return appendTextElement(parent, element, value.toString());
    }


    /**
     * Get the first child {@link org.w3c.dom.Element Element} of an {@link org.w3c.dom.Element Element}.
     * <p>{@link org.w3c.dom.Node Nodes} other than {@link org.w3c.dom.Element Elements} are ignored.
     *
     * @param parent Parent
     * @return The first child {@link org.w3c.dom.Element Element} or null if none exists.
     */
    public static Element firstChildElement(Element parent) {
        Node n = parent.getFirstChild();

        if (n == null || n instanceof Element) {
            return (Element) n;
        } else {
            return nextSiblingElement(n);
        }
    }

    /**
     * Get the next sibling {@link org.w3c.dom.Element Element} of a {@link org.w3c.dom.Node Node}.
     * <p>{@link org.w3c.dom.Node Nodes} other than {@link org.w3c.dom.Element Elements} are ignored.
     *
     * @param n Node
     * @return The first child {@link org.w3c.dom.Element Element} or null if none exists.
     */
    public static Element nextSiblingElement(Node n) {
        do {
            if ((n = n.getNextSibling()) == null) {
                return null;
            }
        }
        while (!(n instanceof Element));

        return (Element) n;
    }


    /**
     * Gets the sibling Element with the indicated name. The sibling
     * searched for must come after the given Element e.
     *
     * @param e    Element to start search from.
     * @param name Name to search for in sibling.
     * @return The sibling Element with the indicated name, or null
     * if the Element could not be found.
     */
    public static Element getSiblingElement(Element e, String name) {
        Element elem = e;
  
        /* 
         * Loop until we find the correct element or until we run 
         * out of siblings. 
         */
        while ((elem = nextSiblingElement(elem)) != null) {
            if (elem.getNodeName().equals(name)) {
                return elem;
            }
        }

        return null;
    }


    /**
     * Gets the value for the sibling Element with the indicated name. The sibling
     * searched for must come after the given Element e.
     *
     * @param e    Element to start search from.
     * @param name Name to search for in sibling.
     * @return The value of the sibling Element with the indicated name, or null
     * if the Element could not be found.
     */
    public static String getSiblingValue(Element e, String name) {
        Element elem = e;

        /* 
         * Loop until we find the correct element or until we run 
         * out of siblings. 
         */
        while ((elem = nextSiblingElement(elem)) != null) {
            if (elem.getNodeName().equals(name)) {
                return elem.getFirstChild().getNodeValue();
            }
        }

        return null;
    }


    /**
     * Gets the child Element with the indicated name. The child
     * searched for must exist one level below the parent, i.e. a real
     * parent-child relation.
     *
     * @param parent Parent Element to start search from.
     * @param name   Name to search for in child.
     * @return The child Element with the indicated name, or null
     * if the Element could not be found.
     */
    public static Element getChildElement(Element parent, String name) {
        Element elem;

        if ((elem = firstChildElement(parent)) == null) {
            return null;
        }

        /* Check first child. */
        if (elem.getNodeName().equals(name)) {
            return elem;
        }

        /* Loop the rest. */
        while ((elem = nextSiblingElement(elem)) != null) {
            if (elem.getNodeName().equals(name)) {
                return elem;
            }
        }

        return null;
    }

    /**
     * Gets the value for the child Element with the indicated name. The child
     * searched for must exist one level below the parent, i.e. a real
     * parent-child relation.
     *
     * @param parent Parent Element to start search from.
     * @param name   Name to search for in child.
     * @return The value for the child Element with the indicated name, or null
     * if the Element could not be found.
     */
    public static String getChildElementValue(Element parent, String name) {
        Element elem;

        if ((elem = firstChildElement(parent)) == null) {
            return null;
        }

        /* Check first child. */
        if (elem.getNodeName().equals(name)) {
            return elem.getFirstChild().getNodeValue();
        }

        /* Loop the rest. */
        while ((elem = nextSiblingElement(elem)) != null) {
            if (elem.getNodeName().equals(name)) {
                return elem.getFirstChild().getNodeValue();
            }
        }

        return null;
    }

    /**
     * Get the target namespace corresponding to a prefix.
     *
     * @param e      Element
     * @param prefix Prefix
     * @return Namespace URI
     */
    public static String getNamespace(Element e, String prefix) {
        String nsURI = null;
        Node n;

        while ((nsURI = e.getAttribute(prefix != null ? "xmlns:" + prefix : "xmlns")) == null &&
                (n = e.getParentNode()) != null && n instanceof Element) {
            e = (Element) n;
        }

        return nsURI;
    }

    /**
     * Get the defining target namespace of this element
     *
     * @param e Element
     * @return Namespace URI
     */
    public static String getDefiningNamespace(Element e) {
        return e.lookupNamespaceURI(e.getPrefix());
    }

    /**
     * Write the XML-encoding of a {@link Document Document} to an
     * {@link java.io.OutputStream OutputStream}.
     *
     * @param d   Document
     * @param out Stream
     * @throws IOException If anything unexpected happens...
     */
    public static void writeXML(Document d, OutputStream out) throws IOException {
        DOMImplementationLS DOMiLS = (DOMImplementationLS) d.getImplementation();
        ;
        LSOutput LSO = DOMiLS.createLSOutput();
        LSO.setByteStream(out);
        LSSerializer LSS = DOMiLS.createLSSerializer();
        if (!LSS.write(d, LSO)) {
            throw new IOException("[Serialization failed!]");
        }
    }

    public static void writeXML(Element e, OutputStream out) throws IOException {
        DOMImplementationLS DOMiLS = (DOMImplementationLS) e.getOwnerDocument().getImplementation();
        ;
        LSOutput LSO = DOMiLS.createLSOutput();
        LSO.setByteStream(out);
        LSSerializer LSS = DOMiLS.createLSSerializer();
        if (!LSS.write(e, LSO)) {
            throw new IOException("[Serialization failed!]");
        }
    }

    /*
     * Write the XML-encoding of a {@link Document Document} to a byte array.
     */
    public static byte[] writeXML(Document d) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeXML(d, baos);
        baos.close();
        return baos.toByteArray();
    }

    public static byte[] writeXML(Element e) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeXML(e, baos);
        baos.close();
        return baos.toByteArray();
    }

    public static String getPrefix(Node n) {
        String s = n.getNodeName();
        int i = s.indexOf(':');
        return i < 0 ? null : s.substring(0, i);
    }

    public static String getLocalName(Node n) {
        String s = n.getNodeName();
        int i = s.indexOf(':');
        return i < 0 ? s : s.substring(i + 1);
    }

    public static boolean booleanValue(String s) {
        if (s.equals("true") || s.equals("1")) {
            return true;
        } else if (s.equals("false") || s.equals("0")) {
            return false;
        } else {
            throw new IllegalArgumentException("Not an XML boolean: " + s);
        }
    }

    /**
     * Centralized DocumentBuilderFactory creator/implemenation
     *
     * @return DocumentBuilderFactory
     */
    public static DocumentBuilderFactory createDocumentBuilderFactory() {
        if (class_document_builder_factory == null) {
            return DocumentBuilderFactory.newInstance();
        }
        return DocumentBuilderFactory.newInstance(class_document_builder_factory, DOMUtil.class.getClassLoader());
    }

    /**
     * Centralized Document creator/implemenation
     *
     * @return Document
     */
    public static Document createDocument() {
        try {
            DocumentBuilderFactory dbf = createDocumentBuilderFactory();
            dbf.setNamespaceAware(true);
            return dbf.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

}
