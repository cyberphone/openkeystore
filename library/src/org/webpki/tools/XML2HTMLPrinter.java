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
package org.webpki.tools;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import java.util.Vector;

import java.net.URLEncoder;

import org.webpki.util.HTMLEncoder;
import org.webpki.util.HTMLHeader;
import org.webpki.util.DebugFormatter;


public class XML2HTMLPrinter {
    public static final String LINK = "%L%";                    // Macro for NS link with no enconding
    public static final String URL_ENC_LINK = "%U%";            // Macro for NS link with URL enconding
    public static final String URL_ENC_ENC_LINK = "%K%";        // Macro for NS link with URL**2 enconding
    public static final String URL_HEX_LINK = "%H%";            // Macro for NS link with URL HEX enconding
    public static final String NSVALUE_COLOR = "#008000";       // Needed outside for A STYLE

    private static final String CDATA_BEGIN = "<![CDATA[";
    private static final String CDATA_END = "]]>";

    private XML2HTMLPrinter() {
    }

    ;   // Only internal

    private static final int ELEMENT_STANDARD = 0;
    private static final int ELEMENT_COMMENT = 1;
    private static final int ELEMENT_CDATA = 2;

    private static final int FIDX_INDENT = 0;
    private static final int FIDX_NEWLINE = 1;
    private static final int FIDX_COMMENT_BEGIN = 2;
    private static final int FIDX_COMMENT_END = 3;
    private static final int FIDX_HEADER_BEGIN = 4;
    private static final int FIDX_HEADER_END = 5;
    private static final int FIDX_ATTVAL_BEGIN = 6;
    private static final int FIDX_ATTVAL_END = 7;
    private static final int FIDX_NSVAL_BEGIN = 8;
    private static final int FIDX_NSVAL_END = 9;
    private static final int FIDX_ELEMENT_BEGIN = 10;
    private static final int FIDX_ELEMENT_END = 11;
    private static final int FIDX_PREFIX_BEGIN = 12;
    private static final int FIDX_PREFIX_END = 13;
    private static final int FIDX_NSLINK_BEGIN = 14;
    private static final int FIDX_NSLINK_END = 15;

    private static final String[] HTML_MODE = {
                                         /*  0 */ "&nbsp;&nbsp;&nbsp;&nbsp;",
                                         /*  1 */ "<br>",
                                         /*  2 */ "<font color=\"#808080\">",
                                         /*  3 */ "</font>",
                                         /*  4 */ "<font color=\"#808080\">",
                                         /*  5 */ "</font>",
                                         /*  6 */ "<font color=\"#0000C0\">",
                                         /*  7 */ "</font>",
                                         /*  8 */ "<font color=\"#008000\">",
                                         /*  9 */ "</font>",
                                         /* 10 */ "<font color=\"#C00000\">",
                                         /* 11 */ "</font>",
                                         /* 12 */ "<font color=\"#008000\">",
                                         /* 13 */ "</font>",
                                         /* 14 */ "<font color=\"#008000\">",
                                         /* 15 */ "</font>"
    };

    private static final String[] TERMINAL_MODE = {
                                         /*  0 */ "   ",
                                         /*  1 */ "\n",
                                         /*  2 */ "",
                                         /*  3 */ "",
                                         /*  4 */ "",
                                         /*  5 */ "",
                                         /*  6 */ "",
                                         /*  7 */ "",
                                         /*  8 */ "",
                                         /*  9 */ "",
                                         /* 10 */ "",
                                         /* 11 */ "",
                                         /* 12 */ "",
                                         /* 13 */ "",
                                         /* 14 */ "",
                                         /* 15 */ ""
    };

    private String xmldata;

    private StringBuilder outdata = new StringBuilder();

    private String[] formatter;

    private String xmlheader;

    private int curr_index;

    private boolean htmlmode;

    private class Keeper {
        Vector<NameValue> items = new Vector<NameValue>();

        class NameValue {
            String name;
            String value;
            Elements children;
            Attributes attr;
            int element_type = ELEMENT_STANDARD;

        }

        void testName(int index, String name) throws IOException {
            if (!getName(index).equals(name)) bad("\"" + name + "\" expected");
        }

        void testValue(int index, String value) throws IOException {
            if (!getString(index).equals(value)) bad("\"" + value + "\" expected");
        }

        String getName(int index) {
            return items.elementAt(index).name;
        }

        boolean isComment(int index) {
            return items.elementAt(index).element_type == ELEMENT_COMMENT;
        }

        boolean isCDATA(int index) {
            return items.elementAt(index).element_type == ELEMENT_CDATA;
        }

        String getString(int index) {
            return items.elementAt(index).value;
        }

        int getInt(int index) {
            return Integer.parseInt(getString(index));
        }

        int size() {
            return items.size();
        }

        NameValue addNameValue() throws IOException {
            boolean next = false;
            int start = curr_index;
            for (; ; ) {
                char c = xmldata.charAt(curr_index);
                if (c == '_' || c == '.' || c == ':' || c == '-' ||
                        (next && c >= '0' && c <= '9') ||
                        (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z')) {
                    next = true;
                    curr_index++;
                } else break;
            }
            if (!next) bad("Missing identifier");
            NameValue nv = new NameValue();
            nv.name = xmldata.substring(start, curr_index);
            items.addElement(nv);
            return nv;
        }

        String getXMLValue(int start, int endp1) throws IOException {
            StringBuilder s = new StringBuilder();
            while (start < endp1) {
                char c = xmldata.charAt(start++);
                s.append(c);
            }
            return s.toString();
        }
    }

    private class Elements extends Keeper {

        Elements getChildElements(int index) {
            return items.elementAt(index).children;
        }

        Attributes getAttributes(int index) {
            return items.elementAt(index).attr;
        }

        void getComment() throws IOException {
            int start = curr_index - 1;
            curr_index += 2;
            NameValue nv = new NameValue();
            requireAndUpdate('-');
            while (more()) {
                if (testChar('-') && testNextChar('-') && testNextNextChar('>')) {
                    nv.name = xmldata.substring(start, curr_index += 3);
                    nv.element_type = ELEMENT_COMMENT;
                    items.addElement(nv);
                    return;
                }
                curr_index++;
            }
            bad("Unterminated comment");
        }

        void getCDATA() throws IOException {
            int start = curr_index - 1;
            curr_index += 8;
            NameValue nv = new NameValue();
            while (more()) {
                if (testChar(']') && testNextChar(']') && testNextNextChar('>')) {
                    nv.name = xmldata.substring(start, curr_index += 3);
                    nv.element_type = ELEMENT_CDATA;
                    items.addElement(nv);
                    return;
                }
                curr_index++;
            }
            bad("Unterminated CDATA");
        }

        private Elements() throws IOException {
            for (; ; ) {
                scanPastWhiteSpace();
                if (!more() || (testChar('<') && testNextChar('/'))) {
                    break;
                }
                requireAndUpdate('<');
                if (testChar('!')) {
                    if (testNextChar('-')) {
                        getComment();
                        continue;
                    }
                    if (xmldata.substring(curr_index).startsWith(CDATA_BEGIN.substring(1))) {
                        getCDATA();
                        continue;
                    }
                }
                scanPastWhiteSpace();
                NameValue nv = addNameValue();
                scanPastWhiteSpace();
                nv.attr = new Attributes();
                if (!testCharAndUpdate('/')) {
                    requireAndUpdate('>');
                    int start = curr_index;
                    scanPastWhiteSpace();
                    int t = 0;
                    if (testChar('<') &&
                            xmldata.substring(curr_index).startsWith(CDATA_BEGIN) &&
                            (t = xmldata.substring(curr_index).indexOf(CDATA_END)) > 0 &&
                            t == xmldata.substring(curr_index).indexOf(CDATA_END + "</")) {
                        nv.value = xmldata.substring(start, curr_index += t + 3);
                        requireAndUpdate('<');
                    } else if (testChar('<') && !testNextChar('/')) {
                        nv.children = new Elements();
                        requireAndUpdate('<');
                    } else {
                        while (!testChar('<')) {
                            curr_index++;
                            if (!more()) {
                                requireAndUpdate('<');
                            }
                        }
                        nv.value = getXMLValue(start, curr_index++);
                    }
                    requireAndUpdate('/');
                    scanPastWhiteSpace();
                    start = curr_index;
                    for (; ; ) {
                        if (!more()) {
                            requireAndUpdate('>');
                        }
                        char c = xmldata.charAt(curr_index);
                        if (c != ' ' && c != '\t' && c != '>') {
                            curr_index++;
                        } else {
                            String rid = getXMLValue(start, curr_index);
                            if (!rid.equals(nv.name)) {
                                bad("Unmatched element '" + rid + "'");
                            }
                            break;
                        }
                    }
                }
                requireAndUpdate('>');
            }
        }
    }

    private class Attributes extends Keeper {
        private Attributes() throws IOException {
            while (!testChar('>') && !testChar('/') && !testChar('?')) {
                NameValue nv = addNameValue();
                scanPastWhiteSpace();
                requireAndUpdate('=');
                scanPastWhiteSpace();
                requireAndUpdate('"');
                int start = curr_index;
                for (; ; ) {
                    if (!more()) {
                        requireAndUpdate('"');
                    }
                    if (testChar('"')) {
                        nv.value = getXMLValue(start, curr_index++);
                        break;
                    } else {
                        curr_index++;
                    }
                }
                scanPastWhiteSpace();
            }
        }
    }

    private Elements parse(String xmlin) throws IOException {
        xmldata = xmlin;
        curr_index = 0;
        if (xmldata.indexOf("<?xml") == 0) {
            curr_index += 5;
            scanPastWhiteSpace();
            Attributes attr = new Attributes();
            int i = attr.size();
            if (i < 1 || i > 2) bad("Bad XML header");
            attr.testName(0, "version");
            attr.testValue(0, "1.0");
            if (i > 1) {
                attr.testName(1, "encoding");
                attr.testValue(1, "UTF-8");
            }
            requireAndUpdate('?');
            requireAndUpdate('>');
            xmlheader = xmldata.substring(0, curr_index);
        }
        Elements el = new Elements();
        if (el.size() == 0) bad("Empty XML document");
        if (more()) bad("End-of-element mismatch");
        return el;
    }

    private void bad(String what) throws IOException {
        if (curr_index < xmldata.length()) {
            what += "\napproximate position: " + xmldata.substring(curr_index);
        }
        throw new IOException(what);
    }

    private boolean more() {
        return curr_index < xmldata.length();
    }

    private boolean scanPastWhiteSpace() {
        boolean ws = false;
        while (testCharAndUpdate(' ') ||
                testCharAndUpdate('\t') ||
                testCharAndUpdate('\n') ||
                testCharAndUpdate('\r')) {
            ws = true;
        }
        return ws;
    }

    private boolean testChar(char c) {
        if (curr_index < xmldata.length() && xmldata.charAt(curr_index) == c) {
            return true;
        }
        return false;
    }

    private boolean testNextChar(char c) {
        curr_index++;
        boolean result = testChar(c);
        curr_index--;
        return result;
    }

    private boolean testNextNextChar(char c) {
        curr_index += 2;
        boolean result = testChar(c);
        curr_index -= 2;
        return result;
    }

    private boolean testCharAndUpdate(char c) {
        if (testChar(c)) {
            curr_index++;
            return true;
        }
        return false;
    }

    private void requireAndUpdate(char c) throws IOException {
        if (!testCharAndUpdate(c)) bad("'" + c + "' expected");
    }

    private void newline() {
        outdata.append(formatter[FIDX_NEWLINE]);
    }

    private void putvalue(String value) {
        if (htmlmode) {
            value = HTMLEncoder.encode(value);
        }
        outdata.append(value);
    }

    private void putformat(int index) {
        outdata.append(formatter[index]);
    }

    private void indent(int level) {
        for (int h = 0; h < level; h++) {
            outdata.append(formatter[FIDX_INDENT]);
        }
    }

    private void putprefix(String pfx) {
        putformat(FIDX_PREFIX_BEGIN);
        putvalue(pfx);
        putformat(FIDX_PREFIX_END);
    }

    private void putCDATA(String cdata) {
        putformat(FIDX_ATTVAL_BEGIN);
        putvalue(cdata);
        putformat(FIDX_ATTVAL_END);
    }

    private void putelement(String name) {
        int i = name.indexOf(':');
        if (i > 0) {
            putprefix(name.substring(0, i));
            outdata.append(':');
            name = name.substring(i + 1);
        }
        putformat(FIDX_ELEMENT_BEGIN);
        putvalue(name);
        putformat(FIDX_ELEMENT_END);
    }

    private void printElements(Elements e, int level) throws IOException {
        for (int i = 0; i < e.size(); i++) {
            String name = e.getName(i);
            String value = e.getString(i);
            indent(level);
            if (e.isComment(i)) {
                putformat(FIDX_COMMENT_BEGIN);
                putvalue(name);
                putformat(FIDX_COMMENT_END);
                newline();
                continue;
            }
            if (e.isCDATA(i)) {
                putvalue(name);
                newline();
                continue;
            }
            putvalue("<");
            putelement(name);
            Attributes attr = e.getAttributes(i);
            for (int a = 0; a < attr.size(); a++) {
                String aname = attr.getName(a);
                String avalue = attr.getString(a);
                boolean link = false;
                boolean xmlns = aname.startsWith("xmlns");
                if (a == 0) {
                    outdata.append("&nbsp;");
                } else {
                    putvalue(" ");
                }
                int colon = aname.indexOf(':');
                boolean xsi_type = false;
                if (colon > 0) {
                    if ((xsi_type = aname.endsWith(":type")) || aname.startsWith("xml:")) {
                        putprefix(aname.substring(0, colon));
                        outdata.append(':');
                        putformat(FIDX_ATTVAL_BEGIN);
                        putvalue(aname.substring(colon + 1));
                        putformat(FIDX_ATTVAL_END);
                    } else {
                        putformat(FIDX_ATTVAL_BEGIN);
                        putvalue(aname.substring(0, colon));
                        putformat(FIDX_ATTVAL_END);
                        outdata.append(':');
                        putprefix(aname.substring(colon + 1));
                    }
                } else {
                    putformat(FIDX_ATTVAL_BEGIN);
                    putvalue(aname);
                    putformat(FIDX_ATTVAL_END);
                }
                putvalue("=\"");
                if (xmlns) {
                    if (avalue.equals("http://www.w3.org/2001/XMLSchema-instance")) {
                        putformat(FIDX_NSVAL_BEGIN);
                    } else {
                        link = true;
                        String lv = formatter[FIDX_NSLINK_BEGIN];
                        int q = lv.indexOf(LINK);
                        if (q > 0) {
                            lv = lv.substring(0, q) + avalue + lv.substring(q + 3);
                        }
                        q = lv.indexOf(URL_ENC_LINK);
                        if (q > 0) {
                            lv = lv.substring(0, q) + URLEncoder.encode(avalue, "UTF-8") + lv.substring(q + 3);
                        }
                        q = lv.indexOf(URL_ENC_ENC_LINK);
                        if (q > 0) {
                            lv = lv.substring(0, q) + URLEncoder.encode(URLEncoder.encode(avalue, "UTF-8"), "UTF-8") + lv.substring(q + 3);
                        }
                        q = lv.indexOf(URL_HEX_LINK);
                        if (q > 0) {
                            lv = lv.substring(0, q) + DebugFormatter.getHexString(avalue.getBytes("UTF-8")) + lv.substring(q + 3);
                        }
                        outdata.append(lv);
                    }
                }


                colon = avalue.indexOf(':');
                if (xsi_type && colon > 0) {
                    putprefix(avalue.substring(0, colon));
                    outdata.append(':');
                    putvalue(avalue.substring(colon + 1));
                } else {
                    putvalue(avalue);
                }
                if (xmlns) {
                    putformat(link ? FIDX_NSLINK_END : FIDX_NSVAL_END);
                }
                putvalue("\"");
            }
            Elements ch = e.getChildElements(i);
            if (value == null && (ch == null || ch.size() == 0)) {
                putvalue("/>");
                newline();
            } else {
                if (value == null) {
                    putvalue(">");
                    newline();
                    printElements(ch, level + 1);
                    indent(level);
                } else {
                    putvalue(">");
                    int spacecnt = 0;
                    int n = 0;
                    boolean cdata = false;
                    if (value.indexOf(CDATA_BEGIN) == 0 &&
                            value.indexOf(CDATA_END) == value.length() - 3) {
                        cdata = true;
                        value = value.substring(CDATA_BEGIN.length(), value.length() - 3);
                        putCDATA(CDATA_BEGIN);
                    }
                    while (n < value.length()) {
                        char c = value.charAt(n++);
                        if (c == ' ') {
                            if (++spacecnt == 2) {
                                outdata.append("&nbsp;");
                                spacecnt = 0;
                            } else {
                                putvalue(" ");
                            }
                            continue;
                        } else {
                            spacecnt = 0;
                            if (c == '\n') {
                                newline();
                                continue;
                            }
                        }
                        putvalue("" + c);
                    }
                    if (cdata) {
                        putCDATA(CDATA_END);
                    }
                }
                putvalue("</");
                putelement(name);
                putvalue(">");
                newline();
            }
        }
    }

    private String printxml(String xmldata) throws IOException {
        Elements r = parse(xmldata);
        if (xmlheader != null) {
            putformat(FIDX_HEADER_BEGIN);
            putvalue(xmlheader);
            putformat(FIDX_HEADER_END);
            newline();
        }
        printElements(r, 0);
        return outdata.toString();
    }

    private static String convert(String xmldata, String[] formatter, boolean htmlmode) throws IOException {
        if (formatter.length != HTML_MODE.length) {
            throw new IOException("formmatter must be " + HTML_MODE.length + " elements");
        }
        XML2HTMLPrinter xp = new XML2HTMLPrinter();
        xp.htmlmode = htmlmode;
        xp.formatter = formatter;
        return xp.printxml(xmldata);
    }

    public static String convert(String xmldata, String[] formatter) throws IOException {
        return convert(xmldata, formatter, true);
    }

    public static String convert(String xmldata, String htmllink) throws IOException {
        XML2HTMLPrinter xp = new XML2HTMLPrinter();
        xp.htmlmode = true;
        xp.formatter = new String[HTML_MODE.length];
        for (int q = 0; q < HTML_MODE.length; q++) {
            xp.formatter[q] = HTML_MODE[q];
        }
        xp.formatter[FIDX_NSLINK_BEGIN] = htmllink;
        xp.formatter[FIDX_NSLINK_END] = "</a>";
        return xp.printxml(xmldata);
    }

    public static String convert(String xmldata) throws IOException {
        return convert(xmldata, HTML_MODE, true);
    }

    public static void main(String argv[]) throws IOException {
        if (argv.length == 0 ||
                (argv.length == 2 && !argv[0].equals("-t")) ||
                argv.length > 2) {
            System.out.println("XML2HTMLPrinter [-t] xmldata\n     -t  formatted for terminal view");
            System.exit(3);
        }
        File f = new File(argv[argv.length - 1]);
        DataInputStream in = new DataInputStream(new FileInputStream(f));
        byte msg[] = new byte[(int) f.length()];
        in.readFully(msg);
        in.close();
        String s = XML2HTMLPrinter.convert(new String(msg, "UTF-8"),
                argv.length == 2 ? TERMINAL_MODE : HTML_MODE,
                argv.length == 1);
        if (argv.length == 2) {
            System.out.println(s);
        } else {
            System.out.println(HTMLHeader.createHTMLHeader(false, true, null, null).append(s).append("</body></html>"));
        }
    }

}
