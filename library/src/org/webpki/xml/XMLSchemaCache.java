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

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.xml.XMLConstants;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import javax.xml.validation.SchemaFactory;

import javax.xml.transform.dom.DOMSource;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import org.webpki.util.ArrayUtil;

/**
 * Repository for schemas and classes for wrapping XML elements as Java objects.
 * <p>The schema cache is used to handle XML messages for an application, keeping
 * some of the XML-related details out of the application code.
 * <p>The schema cache stores the XML schemas/DTDs used by the application for
 * fast and reliable access. In doing that, it also keeps track of what target
 * namespaces are allowed to be used in messages (protecting the application from
 * corrupt or unknown messages and schemas).
 * <p>The schema cache also stores the association of specific XML elements to
 * {@link XMLObjectWrapper wrapper classes} that convert that element/message to and
 * from XML form, allowing the application to access messages as Java objects.
 * <p>The schema cache itself will not remember schemas or wrappers between sessions.
 * <h3>A small example</h3>
 * An example on how to write {@link XMLObjectWrapper wrapper classes} is provided with the
 * distribution.
 * <p><b>Initialization</b>
 * <pre>
 *   XMLSchemaCache cache = new XMLSchemaCache ();
 *
 *   cache.addSchemaFromFile("b2b.xsd");
 *
 *   cache.addWrapper ("com.example.xmlwrappers.Order");
 *   cache.addWrapper ("com.example.xmlwrappers.RequestForQuote");
 *   cache.addWrapper ("com.example.xmlwrappers.Quote");
 *   cache.addWrapper ("com.example.xmlwrappers.Invoice");
 * </pre>
 * The {@link #addSchemaFromFile addSchemaFromFile method} parses the schema file
 * to find it's target namespace. {@link XMLObjectWrapper Wrapper classes} themselves provide
 * information on what element (of what target namespace) they handle.
 * <p><b>Use</b>
 * <pre>
 *   public void processMessage(byte[] xmlMessage) throws ...
 *     {
 *       XMLObjectWrapper message = cache.wrap(xmlMessage);
 *
 *       if(message instanceof Order)
 *         {
 *           Order order = (Order)message;
 *           erpSystem.enterOrder(order.customer(), order.orderNumber(), order.orderLines());
 *         }
 *       else if(message instanceof RequestForQuote)
 *         {
 *           RequestForQuote rfq = (RequestForQuote)rfq;
 *           Quote quote = new Quote(rfq.requestNumber(),
 *                                   erpSystem.getQuote(rfq.customer(), rfq.itemList()));
 *           sendMessage(quote.toXML());
 *         }
 *     }
 * </pre>
 */
public class XMLSchemaCache {
    private static String class_schema_factory;

    private Hashtable<ElementID, Class<?>> classMap;

    private Hashtable<String, byte[]> knownURIs;

    private Vector<DOMSource> schema_stack;

    private DocumentBuilder xsd_parser;

    private DocumentBuilder xml_parser;

    private static class ElementID {
        String namespace, element;

        ElementID(String namespace, String element) {
            this.namespace = namespace;
            this.element = element;
        }

        public int hashCode() {
            return namespace.hashCode() ^ element.hashCode();
        }

        public boolean equals(Object o) {
            return o instanceof ElementID &&
                    namespace.equals(((ElementID) o).namespace) &&
                    element.equals(((ElementID) o).element);
        }
    }


    public XMLSchemaCache() throws IOException {
        classMap = new Hashtable<ElementID, Class<?>>();
        knownURIs = new Hashtable<String, byte[]>();
        schema_stack = new Vector<DOMSource>();
        DocumentBuilderFactory dbf = DOMUtil.createDocumentBuilderFactory();
        dbf.setNamespaceAware(true);
        try {
            xsd_parser = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new IOException(e);
        }
    }


    /**
     * Forces the use of a specific implementation
     *
     * @param schema_factory Class name
     */
    public static void forceSchemaFactory(String schema_factory) {
        class_schema_factory = schema_factory;
    }


    public void addSchema(InputStream is) throws IOException {
        addSchema(ArrayUtil.getByteArrayFromInputStream(is));
    }


    public void addSchemaFromFile(String fname) throws IOException {
        addSchema(new FileInputStream(new File(fname)));
    }


    public void addSchema(byte[] schema) throws IOException {
        Enumeration<byte[]> schemas = knownURIs.elements();
        while (schemas.hasMoreElements()) {
            if (ArrayUtil.compare(schemas.nextElement(), schema)) {
                return;
            }
        }
        try {
            Document document = xsd_parser.parse(new ByteArrayInputStream(schema));
            Element element = document.getDocumentElement();
            // Add more checks?
            String target_namespace = element.getLocalName().equals("schema") ? element.getAttribute("targetNamespace") : null;
            if (target_namespace == null) {
                throw new IOException("Schema did not decode");
            }
            byte[] old = knownURIs.get(target_namespace);
            if (old == null) {
                knownURIs.put(target_namespace, schema);
                schema_stack.add(new DOMSource(document));
            } else {
                throw new IOException("Attempt to redefine target namespace '" + target_namespace + "'.");
            }
        } catch (SAXException e) {
            throw new IOException(e);
        }
    }


    private XMLObjectWrapper wrap(Element e, String namespace) throws IOException {
        try {
            String element = e.getLocalName();
            Class<?> wrapperClass = classMap.get(new ElementID(namespace, element));
            if (wrapperClass == null) {
                throw new RuntimeException("Unknown element type: " + namespace + ", " + element);
            }
            XMLObjectWrapper r = (XMLObjectWrapper) wrapperClass.newInstance();
            r.createRootObject(e.getOwnerDocument(), e);
            r.schemaCache = this;
            DOMReaderHelper drh = new DOMReaderHelper(e);
            drh.getNext(r.element());
            r.fromXML(drh);
            return r;
        } catch (InstantiationException ie) {
            throw new RuntimeException("Unexpected InstantiationException.");
        } catch (IllegalAccessException iae) {
            throw new RuntimeException("Unexpected IllegalAccessException.");
        }
    }


    /**
     * Wrap a parsed XML document using the appropriate {@link XMLObjectWrapper wrapper class}.
     * <p>An instance of the appropriate {@link XMLObjectWrapper wrapper class} is created and
     * populated using it's {@link XMLObjectWrapper#fromXML(DOMReaderHelper) fromXML method}
     * <p>The document is not validated.
     *
     * @param d Document
     * @return XMLObjectWrapper
     * @throws IOException If anything unexpected happens...
     */
    public XMLObjectWrapper wrap(Document d) throws IOException {
        Element e = d.getDocumentElement();
        String namespace = DOMUtil.getDefiningNamespace(e);
        return wrap(e, namespace);
    }

    XMLObjectWrapper wrap(Element e) throws IOException {
        XMLObjectWrapper o = wrap(e, DOMUtil.getDefiningNamespace(e));
        return o;
    }

    public XMLObjectWrapper wrap(XMLCookie cookie) throws IOException {
        return wrap(cookie.element);
    }

    public boolean hasWrapper(Element e) {
        return classMap.containsKey(new ElementID(DOMUtil.getDefiningNamespace(e), e.getLocalName()));
    }

    /**
     * Add a {@link XMLObjectWrapper wrapper class}.
     *
     * @param instance Class instance
     * @throws IOException If anything unexpected happens...
     */
    public void addWrapper(XMLObjectWrapper instance) throws IOException {
        instance.schemaCache = this;
        instance.init();
        classMap.put(new ElementID(instance.namespace(), instance.element()), instance.getClass());
    }

    /**
     * Add a {@link XMLObjectWrapper wrapper class}.
     *
     * @param wrapperClass Class object
     * @throws IOException If anything unexpected happens...
     */
    public void addWrapper(Class<? extends XMLObjectWrapper> wrapperClass) throws IOException {
        try {
            addWrapper(wrapperClass.newInstance());
        } catch (InstantiationException ie) {
            throw new IllegalArgumentException("Class " + wrapperClass.getName() +
                    " is not a valid xml wrapper (InstantiationException instantiating).");
        } catch (IllegalAccessException iae) {
            throw new IllegalArgumentException("Class " + wrapperClass.getName() +
                    " is not a valid xml wrapper (IllegalAccessException instantiating).");
        }
    }


    /**
     * Add a {@link XMLObjectWrapper wrapper class}.
     *
     * @param wrapperClass Wrapper class name
     * @throws IOException If anything unexpected happens...
     */
    public void addWrapper(String wrapperClass) throws IOException {
        try {
            addWrapper(Class.forName(wrapperClass).asSubclass(XMLObjectWrapper.class));
        } catch (ClassNotFoundException cnfe) {
            throw new IllegalArgumentException("Class " + wrapperClass +
                    " can't be found (ClassNotFoundException).");
        }
    }

    /**
     * Add a number of {@link XMLObjectWrapper wrapper classes}.
     *
     * @param classes String array of wrapper class names
     * @throws IOException If anything unexpected happens...
     */
    public void addWrappers(String[] classes) throws IOException {
        for (int i = 0; i < classes.length; i++) {
            addWrapper(classes[i]);
        }
    }

    /**
     * Get the list of registered wrapper classes.
     * <p>Can be used to extract and store the set of wrapper classes between sessions.
     *
     * @return String of wrapper class names
     */
    public String[] getWrapperClasses() {
        String[] r = new String[classMap.size()];

        Enumeration<?> e = classMap.elements();
        for (int i = 0; i < r.length; i++) {
            r[i] = ((Class<?>) e.nextElement()).getName();
        }

        return r;
    }

    /**
     * Get the XML schema associated with a target namespace.
     *
     * @param target_namespace The namespace
     * @return The XML schema as a blob.
     */
    public byte[] getSchema(String target_namespace) {
        return knownURIs.get(target_namespace);
    }

    /**
     * Get the list of known target namespaces.
     *
     * @return String array of namespaces
     */
    public String[] getTargetNamespaces() {
        String[] r = new String[knownURIs.size()];

        Enumeration<String> e = knownURIs.keys();
        for (int i = 0; i < r.length; i++) {
            r[i] = e.nextElement();
        }

        return r;
    }


    public synchronized Document validate(InputStream is) throws IOException {
        try {
            if (xml_parser == null) {
                DocumentBuilderFactory dbf = DOMUtil.createDocumentBuilderFactory();
                dbf.setNamespaceAware(true);
                dbf.setSchema((class_schema_factory == null ?
                        SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI) :
                        SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI, class_schema_factory, this.getClass().getClassLoader())
                ).newSchema(schema_stack.toArray(new DOMSource[0])));
                xml_parser = dbf.newDocumentBuilder();
                xml_parser.setErrorHandler(new ErrorHandler() {

                    @Override
                    public void warning(SAXParseException exception) throws SAXException {
                        throw exception;
                    }

                    @Override
                    public void error(SAXParseException exception) throws SAXException {
                        throw exception;
                    }

                    @Override
                    public void fatalError(SAXParseException exception) throws SAXException {
                        throw exception;
                    }
                });
            }
            return xml_parser.parse(is);
        } catch (SAXException e) {
            throw new IOException(e);
        } catch (ParserConfigurationException e) {
            throw new IOException(e);
        }
    }

    public Document validate(byte[] xmldata) throws IOException {
        return validate(new ByteArrayInputStream(xmldata));
    }


    public Document validate(Document d) throws IOException {
        return validate(DOMUtil.writeXML(d));
    }


    public Document validateXMLFromFile(String fname) throws IOException {
        return validate(new FileInputStream(new File(fname)));
    }

    public XMLObjectWrapper parse(byte[] xmldata) throws IOException {
        return wrap(validate(xmldata));
    }


    public XMLObjectWrapper parse(InputStream is) throws IOException {
        return wrap(validate(is));
    }

    public static void main(String argv[]) throws IOException {
        XMLSchemaCache xmlp = new XMLSchemaCache();
        if (argv.length < 2) {
            System.out.println("Usage: " + xmlp.getClass().getName() + "  schema_1 [schema_2 ... schema_n]  xml_doc");
            System.exit(3);
        }
        int last = argv.length - 1;
        for (int i = 0; i < last; i++) {
            xmlp.addSchemaFromFile(argv[i]);
        }
        Element e = xmlp.validateXMLFromFile(argv[last]).getDocumentElement();
        System.out.println("E=" + e.getLocalName() + " NS=" + DOMUtil.getDefiningNamespace(e));
    }
}
