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
package org.webpki.util;

/**
 * The HTMLEncoder class contains a utility method for converting
 * a string into a format suitable for placing inside a HTML tag
 * parameter, sometimes known as "html encoding".
 * <p>To convert a <CODE>String</CODE>, each character is examined
 * in turn:
 * <UL>
 * <LI>&lt; is converted into &amp;lt;
 * <LI>&gt; is converted into &amp;gt;
 * <LI>&amp; is converted into &amp;amp;
 * <LI>&#034; is converted into &amp;#034;
 * <LI>&#039; is converted into &amp;#039;
 * <LI>All other characters remain the same.
 * </UL>
 */
public class HTMLEncoder {

    /**
     * Converts a string into a htmlencoded string.
     *
     * @param val the <CODE>String</CODE> to be converted.
     * @return the converted <CODE>String</CODE>.
     */
    public static String encode(String val) {
        if (val != null) {
            StringBuilder buf = new StringBuilder(val.length() + 8);
            char c;

            for (int i = 0; i < val.length(); i++) {
                c = val.charAt(i);
                switch (c) {
                    case '<':
                        buf.append("&lt;");
                        break;
                    case '>':
                        buf.append("&gt;");
                        break;
                    case '&':
                        buf.append("&amp;");
                        break;
                    case '\"':
                        buf.append("&#034;");
                        break;
                    case '\'':
                        buf.append("&#039;");
                        break;
                    default:
                        buf.append(c);
                        break;
                }
            }
            return buf.toString();
        } else {
            return new String("");
        }
    }

    @SuppressWarnings("fallthrough")
    public static String encodeWithLineBreaks(byte[] val) {
        if (val != null) {
            StringBuilder buf = new StringBuilder();
            char c;
            boolean indent = true;
            for (int i = 0; i < val.length; i++) {
                c = (char) ((int) val[i] & 0xFF);
                if (c < ' ' && c != '\n') continue;
                if (c >= 127) c = '.';
                if (c == ' ' && indent) buf.append("&nbsp;");
                else {
                    indent = false;
                    switch (c) {
                        case '<':
                            buf.append("&lt;");
                            break;
                        case '>':
                            buf.append("&gt;");
                            break;
                        case '&':
                            buf.append("&amp;");
                            break;
                        case '\"':
                            buf.append("&#034;");
                            break;
                        case '\'':
                            buf.append("&#039;");
                            break;
                        case '\n':
                            buf.append("<br>");
                            indent = true;
                        default:
                            buf.append(c);
                            break;
                    }
                }
            }
            return buf.toString();
        } else {
            return new String("");
        }
    }

}

