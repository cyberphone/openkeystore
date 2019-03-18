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
import java.io.InputStream;

import java.util.Vector;

import org.w3c.dom.Element;
import org.w3c.dom.Document;

import org.webpki.util.ArrayUtil;

/**
 * Base class for java classes whos data can be translated to/from XML documents.
 * <p>A <code>XMLObjectWrapper</code> subclass represents (and handles) a certain
 * <a href="http://www.w3.org/XML/Schema">schema</a>.
 * <p>A <code>XMLObjectWrapper</code> subclass should be capable of {@link #fromXML initializing from}
 * a {@link org.w3c.dom.Document DOM Document} and also {@link #toXML produce} a
 * {@link org.w3c.dom.Document DOM Document} representing it's current state.
 * It <b>must</b> have a public empty (no argument-) constructor to allow
 * the {@link XMLSchemaCache XMLSchemaCache} to create an object instance and
 * call it's {@link #namespace() namespace} and {@link #element() element} methods.
 * <p>A short example of an XMLObjectWrapper using {@link DOMReaderHelper DOMReaderHelper} and
 * {@link DOMWriterHelper DOMWriterHelper} to handle it's XML representation is supplied
 * with the distribution.
 */
public abstract class XMLObjectWrapper {
    // Used by wrap(Element)
    XMLSchemaCache schemaCache;

    boolean output_ns_attribute = true;

    Vector<XMLObjectWrapper> wrapped_children = new Vector<XMLObjectWrapper>();

    DOMWriterHelper parent_writer;

    class XMLRoot {
        Document document;
        Element element;
    }

    XMLRoot parsed_root;  // Set (by wrap) if the XML object was parsed

    void createRootObject(Document document, Element element) {
        parsed_root = new XMLRoot();
        parsed_root.document = document;
        parsed_root.element = element;
    }

    protected boolean inheritIndentFromParent() {
        return true;
    }

    protected void addSchema(String localname) throws IOException {
        schemaCache.addSchema(getResource(localname));
    }

    protected void addWrapper(Class<? extends XMLObjectWrapper> wrapperClass) throws IOException {
        schemaCache.addWrapper(wrapperClass);
    }

    public XMLObjectWrapper[] getWrappedChildren() {
        return wrapped_children.toArray(new XMLObjectWrapper[0]);
    }

    public XMLObjectWrapper() {
    }

    public boolean isWritten() {
        return parsed_root != null;
    }

    public void clearXMLCache() throws IOException {
        parsed_root = null;
    }

    public void setNameSpaceMode(boolean output) {
        if (output_ns_attribute != output) {
            parsed_root = null;
            output_ns_attribute = output;
        }
    }

    protected abstract boolean hasQualifiedElements();

    /**
     * Init method called when the wrapper class is added to an
     * {@link XMLSchemaCache XMLSchemaCache}.
     * The wrapper may override this method to autmatically register the
     * schemas on which it depends.
     *
     * @throws IOException If something unexpected happens...
     * @see #addSchema(String)
     */
    protected abstract void init() throws IOException;

    /**
     * Wrap an element using the {@link XMLSchemaCache XMLSchemaCache} that created
     * this wrapper instance.
     * <p>The wrapper class to be used is determined using
     * {@link XMLSchemaCache#wrap(Element) XMLSchemaCache's wrap(Element) method},
     * which has a known weakness, described in
     * {@link XMLSchemaCache#wrap(Element) it's documentation}, that should be
     * considered when using this method.
     *
     * @param e Element
     * @return Wrapper
     * @throws IOException           If something unexpected happens...
     * @throws IllegalStateException If this wrapper object was not created by an
     *                               {@link XMLSchemaCache XMLSchemaCache}.
     */
    protected XMLObjectWrapper wrap(Element e) throws IOException {
        XMLObjectWrapper o = schemaCache.wrap(e);
        wrapped_children.add(o);
        return o;
    }

    protected boolean hasWrapper(Element e) {
        return schemaCache.hasWrapper(e);
    }


    /**
     * Initialize the object from it's XML-encoding.
     *
     * @param helper Helper
     * @throws IOException If something unexpected happens...
     */
    protected abstract void fromXML(DOMReaderHelper helper) throws IOException;

    /**
     * Get the XML-encoding of the object.
     * <p>This method should only produce an {@link Element Element},
     * it should <b>not</b> be inserted into the document (as this
     * method will not know where in the tree the caller intends to
     * put the element). The document is passed as an argument only
     * because it is needed to produce nodes. The caller is responsible
     * for inserting the element into the tree.
     *
     * @param helper Helper
     * @throws IOException If something unexpected happens...
     */
    protected abstract void toXML(DOMWriterHelper helper) throws IOException;

    /*
     * Get a XML document containing the XML-encoding of the object.
     */
    XMLRoot toXMLDocument() throws IOException {
        if (parsed_root == null) {
            DOMWriterHelper wr = new DOMWriterHelper(this);
            toXML(wr);
            wr.FixStartElement();
        }
        return parsed_root;
    }

    public Element forcedDOMRewrite() throws IOException {
        parsed_root = null;
        return toXMLDocument().element;
    }

    public Element getRootElement() throws IOException {
        return toXMLDocument().element;
    }

    public Document getRootDocument() throws IOException {
        return toXMLDocument().document;
    }

    /**
     * Validate the XML-encoding of the object and validate it against a
     * {@link XMLSchemaCache XMLSchemaCache}.
     * <p>Intended mainly for testing.
     *
     * @param schemaCache Holds schema cache
     * @throws IOException If validation fails.
     */
    public void validate(XMLSchemaCache schemaCache) throws IOException {
        schemaCache.validate(writeXML());
    }

    /**
     * Validate the XML-encoding of the object and validate it against the
     * {@link XMLSchemaCache XMLSchemaCache} that originally created this object.
     * <p>Intended mainly for testing.
     *
     * @throws IOException If validation fails.
     */
    public void validate() throws IOException {
        schemaCache.validate(writeXML());
    }

    /**
     * The <a href="http://www.w3.org/TR/xmlschema-1/#key-targetNS">target namespace)</a>
     * of the element that this class handles.
     *
     * @return Namespace uri
     */
    public abstract String namespace();

    /**
     * The element in the {@link #namespace target namespace} that this class handles.
     *
     * @return Element name
     */
    public abstract String element();

    /**
     * Write the XML-encoding of the object (wrapped in a document as returned by
     * {@link #toXMLDocument toXMLDocument}) to an {@link java.io.OutputStream OutputStream}.
     *
     * @param out Stream
     * @throws IOException If something unexpected happens...
     */
    public void writeXML(OutputStream out) throws IOException {
        toXMLDocument();
        DOMUtil.writeXML(parsed_root.element, out);
    }

    /**
     * Write the XML-encoding of the object (wrapped in a document as returned by
     * {@link #toXMLDocument toXMLDocument}) to a byte array.
     *
     * @return XML binary
     * @throws IOException If something unexpected happens...
     */
    public byte[] writeXML() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        writeXML(baos);
        baos.close();
        return baos.toByteArray();
    }

    /**
     * Convenience method for getting resources through the <code>ClassLoader</code>.
     * <p>This method gets the resource using
     * {@link Class#getResourceAsStream(String) getClass().getResourceAsStream()}
     *
     * @param name Name of resource
     * @return Resource as stream
     * @throws IOException If something unexpected happens...
     */
    protected InputStream getResource(String name) throws IOException {
        InputStream is = getClass().getResourceAsStream(name);
        if (is == null) {
            throw new IOException("Resource " + name + " not found.");
        }
        return is;
    }

    public boolean equals(XMLObjectWrapper other) throws IOException {
        return ArrayUtil.compare(writeXML(), other.writeXML());
    }

    /**
     * Default toString implementation.
     * <p>Returns a string containing the XML representation of this object
     * (wrapped in a document as returned by {@link #toXMLDocument toXMLDocument}).
     *
     * @return XML text
     */
    public String toString() {
        try {
            return new String(writeXML(), "UTF-8");
        } catch (Exception e) {
            return "toString failed: " + e.getMessage();
        }
    }
}
