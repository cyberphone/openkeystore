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


public class XSD2HTMLPrinter {
    public static final int WIDTH = 550;
    public static final int INDENT = 15;

    public static final String LINK = "%L%";                    // Macro for NS link with no enconding
    public static final String URL_ENC_LINK = "%U%";            // Macro for NS link with URL enconding
    public static final String URL_ENC_ENC_LINK = "%K%";        // Macro for NS link with URL**2 enconding
    public static final String URL_HEX_LINK = "%H%";            // Macro for NS link with URL HEX enconding
    public static final String NSVALUE_COLOR = "#008000";       // Needed outside for A STYLE

    private XSD2HTMLPrinter() {
    }

    ;   // Only internal

    private static final int ELEMENT_STANDARD = 0;
    private static final int ELEMENT_COMMENT = 1;
    private static final int ELEMENT_CDATA = 2;

    // private static final int FIDX_INDENT          = 0;
    // private static final int FIDX_NEWLINE         = 1;
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
                                         /*  2 */ "<font color=\"#404040\">",
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

    private String xmldata;

    private StringBuilder outdata = new StringBuilder();

    private String[] formatter;

    private String xmlheader;

    private int line;

    private int pos;

    private int curr_index;

    private boolean htmlmode;

    private boolean paginate;

    private class Keeper {
        Vector<NameValue> items = new Vector<NameValue>();

        class NameValue {
            String name;
            String value;
            int pos;
            int line;
            int emptylinebeforeleave;
            int empty;
            boolean page_break_before;
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

        int getPos(int index) {
            return items.elementAt(index).pos;
        }

        int getEmpty(int index) {
            return items.elementAt(index).empty;
        }

        int getEmptyLinesBeforeLeave(int index) {
            int i = items.elementAt(index).emptylinebeforeleave;
            return i >= 0 ? i : 0;
        }

        int getLine(int index) {
            return items.elementAt(index).line;
        }

        boolean isComment(int index) {
            return items.elementAt(index).element_type == ELEMENT_COMMENT;
        }

        boolean getPageBreakBefore(int index) {
            return items.elementAt(index).page_break_before;
        }

        boolean isCDATA(int index) {
            return items.elementAt(index).element_type == ELEMENT_CDATA;
        }

        String getString(int index) {
            return items.elementAt(index).value;
        }

        int size() {
            return items.size();
        }

        NameValue addNameValue() throws IOException {
            boolean next = false;
            int start = curr_index;
            for (; ; ) {
                char c = xmldata.charAt(curr_index);
                if (c == '_' || c == '.' || c == ':' ||
                        (next && c >= '0' && c <= '9') ||
                        (c == '-') ||
                        (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z')) {
                    next = true;
                    curr_index++;
                } else break;
            }
            if (!next) bad("Missing identifier");
            NameValue nv = new NameValue();
            nv.pos = pos;
            nv.line = line;
            nv.name = xmldata.substring(start, curr_index);
            items.addElement(nv);
            pos += curr_index - start;
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

        void getComment(int emptylines) throws IOException {
            curr_index += 2;
            NameValue nv = new NameValue();
            nv.empty = emptylines;
            requireAndUpdate('-');
            int start = curr_index;
            while (more()) {
                if (testChar('-') && testNextChar('-') && testNextNextChar('>')) {
                    nv.name = xmldata.substring(start, curr_index).trim();
                    curr_index += 3;
                    nv.element_type = ELEMENT_COMMENT;
                    nv.page_break_before = testChar(' ');
                    items.addElement(nv);
                    return;
                }
                if (!scanPastWhiteSpace()) curr_index++;
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
                scanPastWhiteSpace();
                curr_index++;
            }
            bad("Unterminated CDATA");
        }

        private Elements() throws IOException {
            for (; ; ) {
                int emptylines = line;
                if (scanPastWhiteSpace()) {
                    emptylines = line - emptylines - 1;
                } else {
                    emptylines = 0;
                }
                if (!more() || (testChar('<') && testNextChar('/'))) {
                    break;
                }
                requireAndUpdate('<');
                if (testChar('!')) {
                    if (testNextChar('-')) {
                        getComment(emptylines);
                        continue;
                    }
                    if (xmldata.substring(curr_index).startsWith("![CDATA[")) {
                        getCDATA();
                        continue;
                    }
                }
                scanPastWhiteSpace();
                NameValue nv = addNameValue();
                nv.empty = emptylines;
                scanPastWhiteSpace();
                nv.attr = new Attributes();
                if (testCharAndUpdate('/')) {
                    requireAndUpdate('>');
                    nv.page_break_before = testChar(' ');
                } else {
                    requireAndUpdate('>');
                    nv.page_break_before = testChar(' ');
                    int start = curr_index;
                    scanPastWhiteSpace();
                    if (testChar('<') && !testNextChar('/')) {
                        curr_index = start;
                        nv.children = new Elements();
                        requireAndUpdate('<');
                        int q = curr_index - 2;
                        nv.emptylinebeforeleave = -1;
                        while (q > 0) {
                            char c = xmldata.charAt(q--);
                            if (c == '\n') {
                                nv.emptylinebeforeleave++;
                            } else if (c != ' ' && c != '\t' && c != '\r') break;
                        }
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
                    requireAndUpdate('>');
                }
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
            if (c == '\n') {
                line++;
                pos = 0;
            } else {
                pos++;
            }
            curr_index++;
            return true;
        }
        return false;
    }

    private void requireAndUpdate(char c) throws IOException {
        if (!testCharAndUpdate(c)) bad("'" + c + "' expected");
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

    private void putprefix(String pfx) {
        putformat(FIDX_PREFIX_BEGIN);
        putvalue(pfx);
        putformat(FIDX_PREFIX_END);
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

    private void printComment(String name, int level, int empty, boolean page_break_before) {
        int o = level * INDENT;
        int pad = 5;
        String color = "#f0f0f0";
        boolean table = false;
        int topmarg = empty > 0 ? 5 : 15;
        String extra = "";
        if (level == 0) {
            color = "#ffffd8";
            pad = 15;
            if (name.startsWith("- ")) {
                int q = name.indexOf(" -");
                extra = "<center><b>" + name.substring(2, q) + "</b></center><br>";
                name = name.substring(q + 2).trim();
            }
        }
        if (name.startsWith("=====")) {
            int q = name.indexOf('\n');
            name = name.substring(q);
            q = name.indexOf("====");
            name = name.substring(0, q).trim();
            color = "#ffffd8";
            table = true;
        } else if (name.indexOf("- - - -") >= 0) {
            int q = name.indexOf('\n');
            name = name.substring(q);
            q = name.indexOf("- - - -");
            name = name.substring(0, q).trim();
        }
        outdata.append("<table cellpadding=\"0\" cellspacing=\"0\" style=\"" + (paginate && page_break_before ? "page-break-before:always;" : "") +
                "background:" + color + ";margin-left:" + o + "px;" +
                "padding:" + pad + "px;margin-top:" + topmarg + "px;margin-bottom:5px;" +
                "font-weight: normal;border-width:1px;border-style:solid;border-color:#a0a0a0\"><tr><td " +
                "style=\"width:" + (WIDTH - o - pad - pad) + "px\"");
        if (table) {
            outdata.append(" align=\"center\"><table cellpadding=\"0\" cellspacing=\"0\"><tr><td align=\"left\"");
        }
        outdata.append(">");
        putformat(FIDX_COMMENT_BEGIN);
        outdata.append(extra);
        int i = 0;
        while (i < name.length()) {
            char c = name.charAt(i);
            if (level == 0 && c == '"') {
                boolean space = true;
                for (int q = 0; q < i; q++) {
                    if (name.charAt(q) != ' ') {
                        space = false;
                        break;
                    }
                }
                if (space) {
                    int q = name.substring(i + 1).indexOf('"');
                    if (q > 50) {
                        outdata.append("<div style=\"margin-left:15px\"><i>");
                        putvalue(name.substring(++i, q + i));
                        outdata.append("</i>&nbsp;");
                        name = name.substring(i + q + 1);
                        q = name.indexOf('\n');
                        putvalue(name.substring(0, q));
                        name = name.substring(++q);
                        outdata.append("</div>&nbsp;<br>");
                        i = 0;
                        continue;
                    }
                }
            }
            if (c == '\n' || c == '\r') {
                if (i > 1 && name.charAt(i - 1) == ' ') {
                    putvalue(name.substring(0, i - 1));
                    if (c == '\r' && name.charAt(i + 1) == '\n') {
                        i++;
                    }
                    outdata.append("<br>");
                    name = name.substring(i + 1);
                    i = 0;
                    continue;
                }
                if (i > 0 && name.charAt(i - 1) == '\n') {
                    putvalue(name.substring(0, i));
                    if (c == '\r' && name.charAt(i + 1) == '\n') {
                        i++;
                    }
                    outdata.append(level == 0 ? "<br>&nbsp;<br>" : "<br><table width=\"1\" height=\"7\"><tr><td></td></tr></table>");
                    name = name.substring(i + 1);
                    i = 0;
                    continue;
                }
            }
            if (c == '.' && (i + 2) < name.length()) {
                char d = name.charAt(i + 1);
                if (d == '\n' || d == '\r' || d == ' ') {
                    if (d == ' ') {
                        d = name.charAt(i + 2);
                        if (d == '\r' || d == '\n') {
                            i++;
                            continue;
                        }
                    }
                    putvalue(name.substring(0, i + 1));
                    outdata.append("&nbsp;");
                    name = name.substring(i + 1);
                    i = 0;
                    continue;
                }
            }
            if (c == 'C') {
                int j = name.indexOf("RFC ");
                if (j >= 0 && j == (i - 2)) {
                    putvalue(name.substring(0, ++i));
                    outdata.append("&nbsp;");
                    name = name.substring(i + 1);
                    i = 0;
                    continue;
                }
            }
            i++;
        }
        putvalue(name);
        putformat(FIDX_COMMENT_END);
        outdata.append("</td></tr></table>");
        if (table) {
            outdata.append("</td></tr></table>");
        }
    }

    private void printElements(Elements e, int level) throws IOException {
        for (int i = 0; i < e.size(); i++) {
            String name = e.getName(i);
            String value = e.getString(i);
            int emptylines = e.getEmpty(i);
            while (emptylines-- > 0) {
                outdata.append("&nbsp;<br>");
            }
            if (e.isComment(i)) {
                printComment(name, level, e.getEmpty(i), e.getPageBreakBefore(i));
                continue;
            }
            if (e.isCDATA(i)) {
                putvalue(name);
                continue;
            }
            Attributes attr = e.getAttributes(i);
            int line = -1;
            int lines = 0;
            int pos = 0;
            for (int a = 0; a < attr.size(); a++) {
                if (attr.getLine(a) != line) {
                    if (lines++ == 0) {
                        pos = attr.getPos(a);
                    } else if (pos != attr.getPos(a)) {
                        throw new IOException("Bad attribute formatting elem=" + name);
                    }
                    line = attr.getLine(a);
                }
            }
            if (lines > 1) {
                outdata.append("<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin-left:" +
                        level * INDENT + "px\"><tr><td valign=\"top\" rowspan=\"" + lines + "\">");
            } else {
                outdata.append("<div style=\"margin-left:" + level * INDENT + "px" +
                        (paginate && e.getPageBreakBefore(i) ? ";page-break-before:always" : "") + "\">");
            }
            putvalue("<");
            putelement(name);
            if (lines > 1) {
                outdata.append("&nbsp;</td><td>");
            }
            for (int a = 0; a < attr.size(); a++) {
                String aname = attr.getName(a);
                String avalue = attr.getString(a);
                boolean link = false;
                boolean xmlns = aname.startsWith("xmlns") ||
                        aname.equals("namespace") ||
                        aname.equals("targetNamespace");
                if (lines > 1) {
                    if (attr.getPos(a) == pos) {
                        if (a > 0) {
                            outdata.append("</td></tr><tr><td>");
                        }
                    } else {
                        putvalue(" ");
                    }
                } else {
                    putvalue(" ");
                }
                int colon = aname.indexOf(':');
                if (colon > 0) {
                    if (xmlns) {
                        putformat(FIDX_ATTVAL_BEGIN);
                        putvalue(aname.substring(0, colon));
                        putformat(FIDX_ATTVAL_END);
                        outdata.append(':');
                        putprefix(aname.substring(colon + 1));
                    } else {
                        putprefix(aname.substring(0, colon));
                        outdata.append(':');
                        putformat(FIDX_ATTVAL_BEGIN);
                        putvalue(aname.substring(colon + 1));
                        putformat(FIDX_ATTVAL_END);
                    }
                } else {
                    putformat(FIDX_ATTVAL_BEGIN);
                    putvalue(aname);
                    putformat(FIDX_ATTVAL_END);
                }
                putvalue("=\"");
                if (xmlns) {
                    if (avalue.equals("http://www.w3.org/2001/XMLSchema")) {
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
                    putvalue(avalue);
                    putformat(link ? FIDX_NSLINK_END : FIDX_NSVAL_END);
                } else {
                    if (name.equals("pattern") || name.endsWith(":pattern")) {
                        putvalue(avalue);
                    } else while (true) {
                        int q = avalue.indexOf(':');
                        if (q > 0) {
                            putprefix(avalue.substring(0, q));
                            avalue = avalue.substring(q);
                        }
                        q = avalue.indexOf('/');
                        if (q > 0) {
                            putvalue(avalue.substring(0, ++q));
                            avalue = avalue.substring(q);
                            continue;
                        }
                        putvalue(avalue);
                        break;
                    }
                }
                putvalue("\"");
            }
            Elements ch = e.getChildElements(i);
            if (value == null && (ch == null || ch.size() == 0)) {
                putvalue("/>");
                if (lines > 1) {
                    outdata.append("</td></tr></table>");
                } else {
                    outdata.append("</div>");
                }
            } else {
                if (value == null) {
                    putvalue(">");
                    if (lines > 1) {
                        outdata.append("</td></tr></table>");
                    } else {
                        outdata.append("</div>");
                    }
                    printElements(ch, level + 1);
                } else {
                    putvalue(">" + value);
                }

                int q = e.getEmptyLinesBeforeLeave(i);
                if (q-- > 0) {
                    outdata.append("&nbsp;<br>");
                }
                if (value != null) {
                    outdata.append("</div>");
                }
                outdata.append("<div style=\"margin-left:" + level * INDENT + "px\">");
                putvalue("</");
                putelement(name);
                putvalue(">");
                outdata.append("</div>");
            }
        }
    }

    private String printxml(String xmldata) throws IOException {
        Elements r = parse(xmldata);
        if (xmlheader != null) {
            outdata.append("<div>");
            putformat(FIDX_HEADER_BEGIN);
            putvalue(xmlheader);
            putformat(FIDX_HEADER_END);
            outdata.append("</div>");
        }
        printElements(r, 0);
        return outdata.toString();
    }


    public static String convert(String xmldata, String[] formatter, boolean paginate) throws IOException {
        if (formatter.length != HTML_MODE.length) {
            throw new IOException("formmatter must be " + HTML_MODE.length + " elements");
        }
        XSD2HTMLPrinter xp = new XSD2HTMLPrinter();
        xp.paginate = paginate;
        xp.htmlmode = true;
        xp.formatter = formatter;
        return xp.printxml(xmldata);
    }

    public static String convert(String xmldata, String htmllink, boolean paginate) throws IOException {
        XSD2HTMLPrinter xp = new XSD2HTMLPrinter();
        xp.paginate = paginate;
        xp.htmlmode = true;
        xp.formatter = new String[HTML_MODE.length];
        for (int q = 0; q < HTML_MODE.length; q++) {
            xp.formatter[q] = HTML_MODE[q];
        }
        xp.formatter[FIDX_NSLINK_BEGIN] = htmllink == null ? xp.formatter[FIDX_NSVAL_BEGIN] : htmllink;
        xp.formatter[FIDX_NSLINK_END] = htmllink == null ? xp.formatter[FIDX_NSVAL_END] : "</a>";
        return xp.printxml(xmldata);
    }

    public static String convert(String xmldata) throws IOException {
        return convert(xmldata, HTML_MODE, false);
    }

    public static void main(String argv[]) throws IOException {
        if (argv.length != 1) {
            System.out.println("XSD2HTMLPrinter xmlscheme");
            System.exit(3);
        }
        File f = new File(argv[argv.length - 1]);
        DataInputStream in = new DataInputStream(new FileInputStream(f));
        byte msg[] = new byte[(int) f.length()];
        in.readFully(msg);
        in.close();
        System.out.println(HTMLHeader.createHTMLHeader(false, true, null, null).append(
                XSD2HTMLPrinter.convert(new String(msg, "UTF-8"), (String) null, false)).
                append("</body></html>"));
    }

}
