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

import java.math.BigInteger;
import java.math.BigDecimal;
import java.util.EnumSet;
import java.util.Vector;
import java.util.GregorianCalendar;

import java.text.SimpleDateFormat;

import org.w3c.dom.Element;
import org.w3c.dom.Document;
import org.w3c.dom.Text;
import org.w3c.dom.CDATASection;

import org.webpki.util.Base64;
import org.webpki.util.StringUtil;
import org.webpki.util.ISODateTime;

/**
 * Utility class making creation of DOM documents easier in simple cases.
 * <p>The DOMWriterHelper holds a cursor, the
 * <a name="current"><code><b>&quot;current element&quot;</b></code></a>,
 * pointing at the last element created, to simplify building substructures
 * and adding attributes.
 * <p>Note that all <code>addXXXX</code> methods, and {@link #getParent() getParent},
 * do not necessarily act on the &quot;current element&quot; but on the last non-text element
 * created or visited. This is a consequence of the simplified model we use in this class
 * were elements either contain text or subelements (not both). This distinction makes
 * <code>addXXXX</code> methods irrelevant when we are at a text element, instead we then let
 * it act on that text element's parent allowing code like
 * <pre>
 *   helper.addChildElement(&quot;address&quot;);
 *   helper.addString(&quot;street&quot;, &quot;1 X-Obi Drive&quot;);
 *   helper.addString(&quot;city&quot;, &quot;Palo Alto&quot;);
 *   helper.addString(&quot;state&quot;, &quot;CA&quot;);</pre>
 * to create an element <code>address</code> with three subelements. If
 * <code>addTextElement</code> had always operated on the &quot;current element&quot;,
 * we would have had to insert {@link #getParent() getParent} between the
 * <code>addTextElement</code>s. As an additional consequence of this design,
 * it wouldn't make sense to let {@link #getParent() getParent} operate
 * on text elements. Hence {@link #getParent() getParent} will move the cursor
 * to the parent's parent if the &quot;current element&quot; is a text element.
 * <p>A more technical explanation of this would be that there are in fact two
 * cursors, one &quot;element insertion cursor&quot; and one
 * &quot;attribute setting cursor&quot;, and that <code>setXXXX</code> methods operate on the
 * element pointed out by the &quot;attribute setting cursor&quot; while the
 * navigation ({@link #getParent() getParent}) and element creation (<code>addXXXX</code>)
 * methods operate on the &quot;element insertion cursor&quot;. Then all
 * <code>addXXXX</code> methods and {@link #getParent() getParent} move the
 * &quot;attribute setting cursor&quot; while only {@link #getParent() getParent},
 * {@link #addChildElement(String) addChildElement} and {@link #addWrapped(XMLObjectWrapper) addWrapped}
 * also move the &quot;element insertion cursor&quot; (the &quot;attribute setting cursor&quot;
 * will then point to the same element as the &quot;element insertion cursor&quot;).
 * <h3>A small example</h3>
 * <pre>
 *   DOMWriterHelper helper = new DOMWriterHelper(doc, &quot;example:order&quot;);
 *
 *   helper.setNamespace(&quot;http://www.example.com/xml-schemas/order&quot;);
 *
 *   helper.addString(&quot;buyer&quot;, buyer);
 *
 *   helper.setIntAttribute(&quot;duns&quot;, buyerDUNS);
 *
 *   if(comment != null)
 *     helper.addString(&quot;comment&quot;, comment);
 *   ...</pre>
 * which creates the structure (<code>comment!=null</code> in this case)
 * <pre>
 *   &lt;example:order xmlns:example=&quot;...&quot;&gt;
 *       &lt;buyer duns=&quot;12345&quot;&gt;John Doe&lt;/buyer&gt;
 *       &lt;comment&gt;Urgent!&lt;/comment&gt;
 *       ...
 *   &lt;/example:order&gt;</pre>
 * This example code comes from an example included in the distribution
 * to illustrate how to write an {@link XMLObjectWrapper XMLObjectWrapper}.
 */
public class DOMWriterHelper {
    @SuppressWarnings("unused")
    private DOMWriterHelper() {
    }

    DOMWriterHelper(XMLObjectWrapper o)  // Used in ONE particular place
    {
        temp_instance = o;
    }

    Document doc;

    private XMLObjectWrapper temp_instance;

    private String subprefix;  // set if elementFormDefault="qualified"

    private Element current, navCurrent, startElement;

    private boolean pretty_printing = true;

    private Vector<String> stack = new Vector<String>();

    public String pushPrefix(String subprefix) {
        String oldprefix = this.subprefix;
        stack.add(this.subprefix);
        this.subprefix = subprefix;
        return oldprefix;
    }

    public void popPrefix() {
        subprefix = stack.lastElement();
        stack.removeElementAt(stack.size() - 1);
    }

    public void FixStartElement() {
        // Finish indenting up to (and including) startElement
        while (navCurrent != startElement) {
            getParent();
        }
        if (navCurrent.getFirstChild() != null && pretty_printing) {
            // Indent only if content is non-empty
            navCurrent.appendChild(doc.createTextNode(indent.toString()));
        }
    }

    private Element initializeRootObject(XMLObjectWrapper instance, String prefix) {
        if (instance.hasQualifiedElements()) {
            subprefix = prefix;  // May be null anyway
        }
        doc = DOMUtil.createDocument();
        String ns = instance.namespace();
        Element e = doc.createElementNS(ns, (prefix == null) ? instance.element() : prefix + ":" + instance.element());
        if (instance.output_ns_attribute) {
            e.setAttributeNS("http://www.w3.org/2000/xmlns/", (prefix == null) ? "xmlns" : "xmlns:" + prefix, ns);
        }
        doc.appendChild(e);
        instance.createRootObject(doc, e);
        startElement = current = navCurrent = e;
        if (instance.parent_writer != null)
            indent = new StringBuilder(instance.parent_writer.indent.toString());
        return e;
    }

    public Element initializeRootObject(String prefix) {
        Element e = initializeRootObject(temp_instance, prefix);
        temp_instance = null;
        return e;
    }

    public void setPrettyPrinting(boolean flag) {
        pretty_printing = flag;
    }

    /**
     * Creates a <code>DOMWriterHelper</code> wrapping an <code>XMLObjectWrapper</code>.
     *
     * @param instance XMLObjectWrapper
     * @param prefix   Prefix
     * @throws IOException If anything unexpected happens...
     */
    public DOMWriterHelper(XMLObjectWrapper instance, String prefix) throws IOException {
        initializeRootObject(instance, prefix);
    }


    private StringBuilder indent = new StringBuilder("\n");

    private void increaseIndent() {
        indent.append("  ");
    }


    public void addComment(String comment, boolean indent_flag) {
        if (indent_flag) increaseIndent();
        if (pretty_printing) {
            navCurrent.appendChild(doc.createTextNode(indent.toString()));
        }
        navCurrent.appendChild(doc.createComment(comment));
        if (indent_flag) indent.setLength(indent.length() - 2);
    }

    private Element addElement(Element e) {
        indent.append("  ");
        if (pretty_printing) {
            navCurrent.appendChild(doc.createTextNode(indent.toString()));
        }
        indent.setLength(indent.length() - 2);
        return current = (Element) navCurrent.appendChild(e);
    }

    private Element addElement(String name) {
        return addElement(doc.createElement(subprefix == null ? name : subprefix + ":" + name));
    }


    /**
     * Creates an empty element as a child of the last nontext element created or visited.
     *
     * @param name Element name
     * @return Element
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public Element addChildElement(String name) {
        navCurrent = addElement(name);
        indent.append("  ");
        return navCurrent;
    }

    /**
     * Creates an empty element as a child of the last nontext element created or visited.
     *
     * @param ns   Namespace URI
     * @param name Element name
     * @return Element
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public Element addChildElementNS(String ns, String name) {
        navCurrent = addElement(doc.createElementNS(ns, subprefix == null ? name : subprefix + ":" + name));
        indent.append("  ");
        return navCurrent;
    }

    /**
     * Add a {@link XMLObjectWrapper wrapped element} as a child of the last nontext element created or visited.
     *
     * @param wrapper The {@link XMLObjectWrapper wrapped element}.
     * @throws IOException If anything unexpected happens...
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addWrapped(XMLObjectWrapper wrapper) throws IOException {
        indent.append("  ");
        if (pretty_printing) {
            navCurrent.appendChild(doc.createTextNode((wrapper.inheritIndentFromParent() && wrapper.parsed_root == null)
                    ?
                    indent.toString() : "\n"));
        }
        wrapper.parent_writer = wrapper.inheritIndentFromParent() ? this : null;
        XMLObjectWrapper.XMLRoot r = wrapper.toXMLDocument();
        current = (Element) navCurrent.appendChild((Element) doc.importNode(r.element, true));
        indent.setLength(indent.length() - 2);
    }

    public void addXMLCookie(XMLCookie cookie) throws IOException {
        if (pretty_printing) {
            navCurrent.appendChild(doc.createTextNode("\n"));
        }
        current = (Element) navCurrent.appendChild((Element) doc.importNode(cookie.element, true));
    }

    /**
     * Creates an empty element as a child of the last nontext element created or visited,
     * but without setting the new element as the target of the next <code>addXXX</code> call.
     *
     * @param name Element name
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addEmptyElement(String name) {
        addElement(name);
    }

    /**
     * Add a clone of an existing element as a child of the last nontext element created or visited.
     *
     * @param element The {@link Element element} to clone.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addClone(Element element) {
        if (pretty_printing) {
            navCurrent.appendChild(doc.createTextNode("\n"));
        }
        current = (Element) navCurrent.appendChild((Element) doc.importNode(element, true));
    }

    /**
     * Add a text element to the current element.
     *
     * @param name  The name of the new element.
     * @param value The text content of the new element.
     * @return Text element
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public Text addString(String name, String value) {
        if (value == null) {
            throw new NullPointerException("Null value text elements not allowed.");
        }
        addElement(name);
        return (Text) current.appendChild(doc.createTextNode(value));
    }

    /**
     * Add a text element to the current element.
     *
     * @param ns    Namespace URI
     * @param name  The name of the new element.
     * @param value The text content of the new element.
     * @return Text object
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public Text addStringNS(String ns, String name, String value) {
        if (value == null) {
            throw new NullPointerException("Null value text elements not allowed.");
        }
        addElement(doc.createElementNS(ns, subprefix == null ? name : subprefix + ":" + name));
        return (Text) current.appendChild(doc.createTextNode(value));
    }

    /**
     * Add a CDATA element to the current element.
     *
     * @param name  The name of the new element.
     * @param value The text content of the new element.
     * @return CDATASection
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public CDATASection addCDATA(String name, String value) {
        if (value == null) {
            throw new NullPointerException("Null value CDATA elements not allowed.");
        }
        addElement(name);
        return (CDATASection) current.appendChild(doc.createCDATASection(value));
    }

    /**
     * Add a text element to the current element if the value is non-null.
     *
     * @param name  The name of the new element.
     * @param value The text content of the new element.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addStringConditional(String name, String value) {
        if (value != null) {
            addString(name, value);
        }
    }

    /**
     * Add a text element to the current element.
     *
     * @param name  The name of the new element.
     * @param value The text content of the new element.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addInt(String name, int value) {
        addString(name, Integer.toString(value));
    }

    /**
     * Add a text element to the current element.
     *
     * @param name  The name of the new element.
     * @param value The content of the new element.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addBoolean(String name, boolean value) {
        addString(name, value ? "true" : "false");
    }

    /**
     * Add a text element to the current element.
     * <p>Uses the <i>value</i>'s {@link Object#toString toString} function and is hence useful
     * when value is an object whos {@link Object#toString toString} returns a suitably formatted
     * string representation, for example a {@link java.lang.StringBuilder StringBuilder},
     * {@link java.math.BigInteger BigInteger} or {@link java.math.BigDecimal BigDecimal}.
     *
     * @param name  The name of the new element.
     * @param value The text content of the new element.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addObject(String name, Object value) {
        addString(name, value.toString());
    }

    /**
     * Add a text element to the current element if the value is non-null.
     * <p>Uses the <i>value</i>'s {@link Object#toString toString} function and is hence useful
     * when value is an object whos {@link Object#toString toString} returns a suitably formatted
     * string representation, for example a {@link java.lang.StringBuilder StringBuilder},
     * {@link java.math.BigInteger BigInteger} or {@link java.math.BigDecimal BigDecimal}.
     *
     * @param name  The name of the new element.
     * @param value The text content of the new element.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addObjectConditional(String name, String value) {
        if (value != null) {
            addString(name, value.toString());
        }
    }

    /**
     * Add a text element to the current element.
     * <p>The text content of the new element will be <i>value</i> divided by 10000 and rounded/extended to
     * the desired number of decimals. The rounding used is
     * {@link BigDecimal#ROUND_HALF_UP BigDecimal.ROUND_HALF_UP}, i.e. the standard method of rounding.
     * <p>This datatype corresponds to <a href="http://www.microsoft.com/sql">MS SQL Server</a>'s
     * <code>money</code> (and <code>smallmoney</code>) datatypes.
     *
     * @param name             The name of the new element.
     * @param value            The text content of the new element multiplied by 10000.
     * @param numberOfDecimals The number of decimals to be used the text representation.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addMoney(String name, long value, int numberOfDecimals) {
        addObject(name, new BigDecimal(Long.toString(value)).movePointLeft(4).setScale(numberOfDecimals,
                BigDecimal.ROUND_HALF_UP));
    }

    /**
     * Add a text element to the current element.
     * <p>The text content of the new element will be the <code>Base64</code> encoding
     * of <i>value</i>.
     *
     * @param name  The name of the new element.
     * @param value The unencoded binary value of the new element.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addBinary(String name, byte[] value) {
        addString(name, new Base64(false).getBase64StringFromBinary(value));
    }


    /**
     * Add a text element to the current element.
     * <p>The text content of the new element will be the
     * <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     * encoding of <i>value</i>.
     * <p>The time value will be rounded to the nearest second (the precision
     * of the Java {@link GregorianCalendar GregorianCalendar} class is milliseconds).
     *
     * @param name  The name of the new element.
     * @param value The value of the new element.
     * @param format The chosen format
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addDateTime(String name, 
                            GregorianCalendar value,
                            EnumSet<ISODateTime.DatePatterns> format) {
        addString(name, ISODateTime.formatDateTime(value, format));
    }


    public static String formatDate(GregorianCalendar t) {
        return new SimpleDateFormat("yyyy-MM-dd").format(t.getTime());
    }

    /**
     * Add a text element to the current element.
     * <p>The text content of the new element will be the
     * <code><a href="http://www.w3.org/TR/xmlschema-2/#date">date</a></code>
     * encoding of <i>value</i>.
     *
     * @param name  The name of the new element.
     * @param value The value of the new element.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void addDate(String name, GregorianCalendar value) {
        addString(name, formatDate(value));
    }

    // TODO: document
    public void addList(String name, String[] list) {
        addString(name, StringUtil.tokenList(list));
    }

    /**
     * Set the parent of the last nontext element created or visited as current.
     *
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void getParent() {
        if (navCurrent.getFirstChild() != null && pretty_printing)
        // Indent only if content is non-empty
        {
            navCurrent.appendChild(doc.createTextNode(indent.toString()));
        }
        indent.setLength(indent.length() - 2);
        current = navCurrent = (Element) navCurrent.getParentNode();
    }


    public Element current() {
        return current;
    }

    /**
     * Set an attribute of the current element.
     *
     * @param name  The name of the attribute.
     * @param value The value of the attribute.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void setStringAttribute(String name, String value) {
        StringBuilder s = new StringBuilder();
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"':
                    s.append("&quot;");
                    continue;

                case '\'':
                    s.append("&apos;");
                    continue;

                case '<':
                    s.append("&lt;");
                    continue;

                case '>':
                    s.append("&gt;");
                    continue;

                case '&':
                    s.append("&amp;");
                    continue;

                default:
                    s.append(c);
            }
        }
        current.setAttribute(name, s.toString());
    }

    public void setBinaryAttribute(String name, byte[] value) {
        setStringAttribute(name, new Base64(false).getBase64StringFromBinary(value));
    }


    /**
     * Set an attribute of the current element.
     *
     * @param name  The name of the attribute.
     * @param value The value of the attribute.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void setIntAttribute(String name, int value) {
        setStringAttribute(name, Integer.toString(value));
    }

    /**
     * Set an attribute of the current element.
     *
     * @param name  The name of the attribute.
     * @param value The value of the attribute.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void setBigIntegerAttribute(String name, BigInteger value) {
        setStringAttribute(name, value.toString());
    }

    /**
     * Set an attribute of the current element.
     *
     * @param name  The name of the attribute.
     * @param value The value of the attribute.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void setBooleanAttribute(String name, boolean value) {
        setStringAttribute(name, value ? "true" : "false");
    }

    /**
     * Set an attribute of the current element.
     * <p>Uses the <i>value</i>'s {@link Object#toString toString} function and is hence useful
     * when value is an object whos {@link Object#toString toString} returns a suitably formatted
     * string representation, for example a {@link java.lang.StringBuilder StringBuilder},
     * {@link java.math.BigInteger BigInteger} or {@link java.math.BigDecimal BigDecimal}.
     *
     * @param name  The name of the attribute.
     * @param value The value of the attribute.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void setObjectAttribute(String name, Object value) {
        setStringAttribute(name, value.toString());
    }

    /**
     * Set an attribute of the current element to a long divided by 10000 and rounded/extended to
     * the desired number of decimals. The rounding used is
     * {@link BigDecimal#ROUND_HALF_UP BigDecimal.ROUND_HALF_UP}, i.e. the standard method of rounding.
     * <p>This datatype corresponds to <a href="http://www.microsoft.com/sql">MS SQL Server</a>'s
     * <code>money</code> (and <code>smallmoney</code>) datatypes.
     *
     * @param name             The name of the attribute.
     * @param value            The value of the attribute multiplied by 10000.
     * @param numberOfDecimals The number of decimals to be used the text representation.
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void setMoneyAttribute(String name, long value, int numberOfDecimals) {
        setObjectAttribute(name, new BigDecimal(Long.toString(value)).movePointLeft(4).setScale(numberOfDecimals,
                BigDecimal.ROUND_HALF_UP));
    }

    /**
     * Set an attribute of the current element to a date.
     * <p>The text content of the attribute will be the
     * <code><a href="http://www.w3.org/TR/xmlschema-2/#dateTime">dateTime</a></code>
     * encoding of <i>value</i>.
     * <p>The time value will be rounded to the nearest second (the precision
     * of the Java {@link GregorianCalendar GregorianCalendar} class is milliseconds).
     *
     * @param name  The name of the attribute.
     * @param value The value of the attribute.
     * @param format The chosen format
     * @see <a href="#current">DOMWriterHelper cursor state</a>
     */
    public void setDateTimeAttribute(String name,
                                     GregorianCalendar value,
                                     EnumSet<ISODateTime.DatePatterns> format) {
        setStringAttribute(name, ISODateTime.formatDateTime(value, format));
    }

    // TODO: document
    public void setListAttribute(String name, String[] list) {
        setStringAttribute(name, StringUtil.tokenList(list));
    }

}
