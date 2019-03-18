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

import java.util.EnumSet;
import java.util.NoSuchElementException;
import java.util.GregorianCalendar;

import java.math.BigInteger;
import java.math.BigDecimal;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.webpki.util.Base64;
import org.webpki.util.StringUtil;
import org.webpki.util.ISODateTime;

/**
 * Utility class making traversal of DOM documents easier in simple cases.
 * <p>This class holds the state of a cursor navigating the tree and provides
 * a set of methods for accessing/converting the contents of elements.
 * <p>The cursor is moved after a successful call to <code>getNext()</code>,
 * <code>get<i>Datatype</i>()</code> or <code>get<i>Datatype</i>Conditional()</code>,
 * i.e. after the value is read.
 * <p>{@link #getChild() getChild} and the {@link #getAttributeHelper DOMAttributeReaderHelper}
 * will act on the <a name="last"><code><b>&quot;last visited element&quot;</b></code></a>, hereby defined to mean the
 * element that the cursor pointed at before the last <code>getNext()</code>,
 * <code>get<i>Datatype</i>()</code> or <code>get<i>Datatype</i>Conditional()</code> call, if any.
 * This allows code like
 * <pre>   helper.getNext(&quot;orderline&quot;);
 *   String item = helper.getAttributeHelper().getString(&quot;item&quot;);</pre>
 * to extract the attribute <code>item</code> of element <code>orderline</code>.
 * <h3>A small example</h3>
 * <pre>
 *   DOMReaderHelper helper = new DOMReaderHelper(e);
 *
 *   helper.getNext(&quot;order&quot;);
 *
 *   // Go one level down in the structure.
 *   helper.getChild();
 *
 *   buyer = helper.getString(&quot;buyer&quot;);
 *
 *   buyerDUNS = helper.getAttributeHelper().getInt(&quot;duns&quot;);
 *
 *   comment = helper.getStringConditional(&quot;comment&quot;);
 *   ...</pre>
 * which parses the structure
 * <pre>
 *   &lt;example:order xmlns:example=&quot;...&quot;&gt;
 *       &lt;buyer duns=&quot;12345&quot;&gt;John Doe&lt;/buyer&gt;
 *       &lt;comment&gt;Urgent!&lt;/comment&gt;
 *       ...
 *   &lt;/example:order&gt;</pre>
 * This example code comes from an example included in the distribution
 * to illustrate how to write an {@link XMLObjectWrapper XMLObjectWrapper}.
 */
public class DOMReaderHelper {
    private static final int STATE_BEFORE = -1;
    private static final int STATE_AT = 0;
    private static final int STATE_AFTER = 1;
    private static final int STATE_IN_EMPTY_SET = 2;

    private int state = STATE_BEFORE;
    private Element __current;

    private boolean was_CDATA;  // Really ugly but works...

    public DOMReaderHelper(Element e) {
        __current = e;
    }

    private String text(String name) throws NoSuchElementException {
        was_CDATA = false;
        Element t = current();

        NodeList l = t.getChildNodes();

        if (name != null && !name.equals(DOMUtil.getLocalName(t))) {
            throw new NoSuchElementException("Not at element " + name + ": " + t.getNodeName() + ".");
        }

        if (l.getLength() == 0) {
            return null;
        }
        StringBuilder s = new StringBuilder();
        was_CDATA = true;
        for (int i = 0; i < l.getLength(); i++) {
            Node n = l.item(i);
            short nt = n.getNodeType();
            if (nt != Node.TEXT_NODE && nt != Node.CDATA_SECTION_NODE) {
                throw new NoSuchElementException("Not at a Text/CDATA element: " + t.getNodeName() + ".");
            }
            if (nt == Node.TEXT_NODE) {
                was_CDATA = false;
            }
            s.append(n.getNodeValue());
        }
        return s.toString();
    }

    private String text() throws NoSuchElementException {
        return text(null);
    }

    private void next(String name) throws NoSuchElementException {
        switch (state) {
            case STATE_BEFORE:
                // We are before the first sibling => go to first sibling.
                state = STATE_AT;
                break;
            case STATE_AT:
                // We are at a sibling => go to next sibling if any,
                //                        go after current if current is the last.
                Element t = DOMUtil.nextSiblingElement(__current);
                if (t != null) {
                    __current = t;
                } else {
                    // Changed 20011001: should never go STATE_AFTER, all calls
                    // to next are followed by a call to current() which will then throw
                    // an exception =>
                    // TODO: remove STATE_AFTER completely
                    //state = STATE_AFTER;
                    throw new NoSuchElementException("No more sibling elements.");
                }
                break;
            case STATE_AFTER:
                // We are after the last sibling => this method call is "illegal".
                throw new NoSuchElementException("No more sibling elements.");
            case STATE_IN_EMPTY_SET:
                // We in the child set of an element without children => this method call is "illegal".
                throw new NoSuchElementException("No elements.");
            default:
                throw new RuntimeException("Illegal state.");
        }
        if (name != null && !name.equals(DOMUtil.getLocalName(__current))) {
            throw new NoSuchElementException("Not at element " + name + ": " + __current.getNodeName() + ".");
        }
    }

    private void next() throws NoSuchElementException {
        next(null);
    }


    private Element levelDown() throws NoSuchElementException {
        if (state == STATE_AT || state == STATE_BEFORE) {
            Element t = DOMUtil.firstChildElement(__current);
            if (t != null) {
                state = STATE_BEFORE;
                return __current = t;
            } else {
                state = STATE_IN_EMPTY_SET;
                return null;
            }
        } else {
            throw new NoSuchElementException("Not at an element.");
        }
    }

    private Element levelUp() throws NoSuchElementException {
        if (state != STATE_IN_EMPTY_SET) {
            __current = (Element) __current.getParentNode();
        }
        state = STATE_AT;
        return __current;
    }

    public Element current() throws NoSuchElementException {
        if (state != STATE_AT) {
            throw new NoSuchElementException("Not at an element.");
        } else {
            return __current;
        }
    }
    
    /* *******************************************************************************
          Navigation
       ******************************************************************************* */

    /**
     * Moves the cursor to the first child of the <a href="#last">&quot;last visited element&quot;</a>.
     *
     * @throws NoSuchElementException If there is no <a href="#last">&quot;last visited element&quot;</a>.
     */
    public void getChild() throws NoSuchElementException {
        levelDown();
    }

    /**
     * Moves the cursor to the last element at which {@link #getChild getChild} was called.
     */
    public void getParent() {
        levelUp();
    }

    /**
     * Check if the <a href="#last">&quot;last visited element&quot;</a> has more siblings.
     *
     * @return true if the <a href="#last">&quot;last visited element&quot;</a> has more siblings.
     */
    public boolean hasNext() {
        return state == STATE_BEFORE ||
                (state == STATE_AT && DOMUtil.nextSiblingElement(__current) != null);
    }

    /**
     * Check if the next sibling of <a href="#last">&quot;last visited element&quot;</a>
     * has local name <code><i>name</i></code> (and if exists at all).
     *
     * @param name Name of element
     * @return true if the <a href="#last">&quot;last visited element&quot;</a> has more siblings,
     * and the next sibling has local name <code><i>name</i></code>.
     */
    public boolean hasNext(String name) {
        Element next = (state == STATE_BEFORE) ?
                __current :
                (state == STATE_AT) ?
                        DOMUtil.nextSiblingElement(__current) :
                        null;

        return next != null && DOMUtil.getLocalName(next).equals(name);
    }

    /**
     * Moves the cursor to the next {@link Element Element}.
     *
     * @return The current element.
     * @throws NoSuchElementException If there are no more elements.
     */
    public Element getNext() throws NoSuchElementException {
        next();
        return current();
    }

    /**
     * Checks that the current element has local name <i>name</i> and moves the cursor to the next element.
     *
     * @param name The local element name expected.
     * @return The current element.
     * @throws NoSuchElementException If the current element's local name is not <i>name</i> or
     *                                if there are no more elements.
     */
    public Element getNext(String name) throws NoSuchElementException {
        next(name);
        return current();
    }

    public XMLCookie getXMLCookie(String name) throws NoSuchElementException {
        return new XMLCookie(getNext(name));
    }

    public XMLCookie getXMLCookie() throws NoSuchElementException {
        return new XMLCookie(getNext());
    }

    public String getNamespace() {
        return DOMUtil.getDefiningNamespace(current());
    }

    /* *******************************************************************************
          Attributes
       ******************************************************************************* */
    private DOMAttributeReaderHelper attributeHelper = new DOMAttributeReaderHelper(this);

    /**
     * Get the {@link DOMAttributeReaderHelper DOMAttributeReaderHelper} of this
     * <code>DOMReaderHelper</code>.
     * <p>The {@link DOMAttributeReaderHelper DOMAttributeReaderHelper} gives access
     * to the attributes of the <a href="#last">&quot;last visited element&quot;</a>.
     * <p>Please note that the DOMAttributeReaderHelper returned will follow this
     * DOMReaderHelper's cursor, i.e. it will always act on the current
     * {@link DOMReaderHelper &quot;last visited element&quot;}
     * of this DOMReaderHelper.
     *
     * @return DOMAttributeReaderHelper
     */
    public DOMAttributeReaderHelper getAttributeHelper() {
        return attributeHelper;
    }


    public boolean wasCDATA() {
        return was_CDATA;
    }

    /**
     * Get the text contents of the current {@link Element Element}.
     *
     * @return The text contents of the current {@link Element Element},
     * null if the element is empty.
     * @throws NoSuchElementException if the current element has non-text content or
     *                                if there is no current element.
     */
    public String getString() throws NoSuchElementException {
        next();
        return text();
    }

    /**
     * Get the text contents of the current {@link Element Element}, which must have local name <i>name</i>.
     *
     * @param name The local element name expected.
     * @return The text contents of the current {@link Element Element},
     * null if the element is empty.
     * @throws NoSuchElementException if the current element has non-text content,
     *                                if it's local name is not <i>name</i> or
     *                                if there is no current element.
     */
    public String getString(String name) throws NoSuchElementException {
        next();
        return text(name);
    }

    /**
     * Get the text contents of the current {@link Element Element}, if it exists, is non-empty and has local name <i>name</i>.
     * <p>The cursor will only be moved forward if the local element name matches <i>name</i>.
     *
     * @param name The local element name to test for.
     * @return The text contents of the current {@link Element Element}, if it exists,
     * is non-empty and has local name <i>name</i>, null otherwise.
     * @throws NoSuchElementException if the current element has local name <i>name</i> but
     *                                has non-text content.
     */
    public String getStringConditional(String name) throws NoSuchElementException {
        return hasNext(name) ? getString() : null;
    }

    public int getInt() throws NoSuchElementException {
        return Integer.parseInt(getString());
    }

    public int getInt(String name) throws NoSuchElementException {
        return Integer.parseInt(getString(name));
    }

    public int getIntConditional(String name, int defaultValue) throws NoSuchElementException {
        String s = getStringConditional(name);
        return s != null ? Integer.parseInt(s) : defaultValue;
    }

    public boolean getBoolean() throws NoSuchElementException {
        return DOMUtil.booleanValue(getString());
    }

    public boolean getBoolean(String name) throws NoSuchElementException {
        return DOMUtil.booleanValue(getString(name));
    }

    public boolean getBooleanConditional(String name, boolean defaultValue) throws NoSuchElementException {
        String s = getStringConditional(name);
        return s != null ? DOMUtil.booleanValue(s) : defaultValue;
    }

    public BigDecimal getBigDecimal() throws NoSuchElementException {
        return new BigDecimal(getString());
    }

    public BigDecimal getBigDecimal(String name) throws NoSuchElementException {
        return new BigDecimal(getString(name));
    }

    public BigDecimal getBigDecimalConditional(String name) throws NoSuchElementException {
        String s = getStringConditional(name);
        return s != null ? new BigDecimal(s) : null;
    }

    public BigInteger getBigInteger() throws NoSuchElementException {
        return new BigInteger(getString());
    }

    public BigInteger getBigInteger(String name) throws NoSuchElementException {
        return new BigInteger(getString(name));
    }

    public BigInteger getBigIntegerConditional(String name) throws NoSuchElementException {
        String s = getStringConditional(name);
        return s != null ? new BigInteger(getStringConditional(name)) : null;
    }

    public String[] getList() throws NoSuchElementException {
        return StringUtil.tokenVector(getString());
    }

    public String[] getList(String name) throws NoSuchElementException {
        return StringUtil.tokenVector(getString(name));
    }

    public String[] getListConditional(String name) throws NoSuchElementException {
        String s = getStringConditional(name);
        return s != null ? StringUtil.tokenVector(s) : null;
    }

    public long getMoney() throws NoSuchElementException {
        return getBigDecimal().movePointRight(4).longValue();
    }

    public long getMoney(String name) throws NoSuchElementException {
        return getBigDecimal(name).movePointRight(4).longValue();
    }

    public long getMoneyConditional(String name, long defaultValue) throws NoSuchElementException {
        BigDecimal t = getBigDecimal(name);
        return t != null ? t.movePointRight(4).longValue() : defaultValue;
    }

    public byte[] getBinary() throws NoSuchElementException, IOException {
        return new Base64().getBinaryFromBase64String(getString());
    }

    public byte[] getBinary(String name) throws NoSuchElementException, IOException {
        return new Base64().getBinaryFromBase64String(getString(name));
    }

    public byte[] getBinaryConditional(String name) throws NoSuchElementException, IOException {
        String s = getStringConditional(name);
        return s != null ? new Base64().getBinaryFromBase64String(s) : null;
    }


    public GregorianCalendar getDateTime(EnumSet<ISODateTime.DatePatterns> format) throws NoSuchElementException, IOException {
        return ISODateTime.parseDateTime(getString(), format);
    }

    public GregorianCalendar getDateTime(String name,
                                         EnumSet<ISODateTime.DatePatterns> format) throws NoSuchElementException, IOException {
        return ISODateTime.parseDateTime(getString(name), format);
    }

    public GregorianCalendar getDateTimeConditional(String name,
                                                    EnumSet<ISODateTime.DatePatterns> format) throws NoSuchElementException, IOException {
        String s = getStringConditional(name);
        return s != null ? ISODateTime.parseDateTime(s, format) : null;
    }

    public static GregorianCalendar parseDate(String s) throws IOException {
        GregorianCalendar gc = new GregorianCalendar();
        gc.clear();

        try {
            String t = s;
            int i;

            if (t.startsWith("-")) {
                gc.set(GregorianCalendar.ERA, GregorianCalendar.BC);
                gc.set(GregorianCalendar.YEAR, Integer.parseInt(t.substring(1, i = t.indexOf("-", 1))));
            } else {
                gc.set(GregorianCalendar.ERA, GregorianCalendar.AD);
                gc.set(GregorianCalendar.YEAR, Integer.parseInt(t.substring(0, i = t.indexOf("-"))));
            }
            t = t.substring(i + 1);

            // Check delimiters (whos positions are now known).
            if (t.charAt(2) != '-')
                throw new IOException("Malformed date (" + s + ").");

            gc.set(GregorianCalendar.MONTH, Integer.parseInt(t.substring(0, 2)) - 1);
            t = t.substring(3);

            gc.set(GregorianCalendar.DAY_OF_MONTH, Integer.parseInt(t.substring(0, 2)));
        } catch (NumberFormatException nfe) {
            throw new IOException("Malformed date (" + s + ").");
        }

        return gc;
    }

    public GregorianCalendar getDate() throws NoSuchElementException, IOException {
        return parseDate(getString());
    }

    public GregorianCalendar getDate(String name) throws NoSuchElementException, IOException {
        return parseDate(getString(name));
    }

    public GregorianCalendar getDateConditional(String name) throws NoSuchElementException, IOException {
        String s = getStringConditional(name);
        return s != null ? parseDate(s) : null;
    }

}
