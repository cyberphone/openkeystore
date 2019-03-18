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

import java.util.*;
import java.io.*;

public class StringUtil {
    private static int indexOfNL(String a, String b) {
        int i = a.indexOf(b);
        return i != -1 ? i : a.length();
    }

    private static int indexOfNL(String a, String b, int start) {
        int i = a.indexOf(b, start);
        return i != -1 ? i : a.length();
    }

    /*
     * Splits a string at any of a given set of delimiter.
     * <p>The delimiters will not be present in the resulting substrings.
     * <p>The delimiters may consist of more than one character.
     * <p>If two (or more) delimiters match at the same index (i.e. one is a 
     * prefix of the other) the one occuring first in <code><i>delimiters</i></code>
     * will take precedence.
     * @param includeEmpty Iff true, empty substrings of s will be included
     *                     in the result.
     * @return An array of substrings of s.
     */
    public static String[] splitAtAny(String s, String[] delimiters, boolean includeEmpty) {
        Vector<String> v = new Vector<String>();
        int[] is = new int[delimiters.length];

        for (int i = 0; i < delimiters.length; i++) {
            is[i] = indexOfNL(s, delimiters[i]);
        }

        int start = 0, j, i;

        do {
            j = ArrayUtil.indexOfMin(is);
            i = is[j];

            // We may have i < start if two delimiters, one being a 
            // substring of the other, has matched at the same index.
            if (i >= start) {
                if (includeEmpty || i > start) {
                    v.addElement(s.substring(start, i));
                }

                start = i + delimiters[j].length();

                //s = s.substring(i + delimiter.length());
            }

            is[j] = indexOfNL(s, delimiters[j], start);
        }
        while (i < s.length());

        //if(includeEmpty || s.length() > 0)
        //  v.addElement(s);
        String[] r = new String[v.size()];
        v.copyInto(r);
        return r;
    }

    /*
     * Splits a string at any of a given set of delimiter.
     * <p>The delimiters will not be present in the resulting substrings.
     * Empty substrings of s will not be included in the result.
     * <p>The delimiters may consist of more than one character.
     * <p>This is shorthand for 
     * {@link #splitAtAny(String, String[], boolean) splitAt}<code>(<i>s</i>, <i>delimiter</i>, false)</code>.
     * @return An array of substrings of s.
     */
    public static String[] splitAtAny(String s, String[] delimiters) {
        return splitAtAny(s, delimiters, false);
    }

    /*
     * Splits a string at a given delimiter.
     * <p>The delimiter will not be present in the resulting substrings.
     * <p>The delimiter may consist of more than one character.
     * @param includeEmpty Iff true, empty substrings of s will be included
     *                     in the result.
     * @return An array of substrings of s.
     */
    public static String[] splitAt(String s, String delimiter, boolean includeEmpty) {
        Vector<String> v = new Vector<String>();
        int i;
        while ((i = s.indexOf(delimiter)) >= 0) {
            if (includeEmpty || i > 0) {
                v.addElement(s.substring(0, i));
            }
            s = s.substring(i + delimiter.length());
        }
        if (includeEmpty || s.length() > 0)
            v.addElement(s);
        String[] r = new String[v.size()];
        v.copyInto(r);
        return r;
    }

    /*
     * Splits a string at a given delimiter.
     * <p>The delimiter will not be present in the resulting substrings.
     * Empty substrings of s will not be included in the result.
     * <p>The delimiter may consist of more than one character.
     * <p>This is shorthand for 
     * {@link #splitAt(String, String, boolean) splitAt}<code>(<i>s</i>, <i>delimiter</i>, false)</code>.
     * @return An array of substrings of s.
     */
    public static String[] splitAt(String s, String delimiter) {
        return splitAt(s, delimiter, false);
    }

    // TODO: document
    private static String[] tokenArray(StringTokenizer st) {
        int l = st.countTokens();
        String[] r = new String[l];
        for (int i = 0; i < l; i++) {
            r[i] = st.nextToken();
        }
        return r;
    }

    // TODO: document better
    /*
     * Uses {@link StringTokenizer StringTokenizer}.
     */
    public static String[] tokenVector(String s, String delimiters) {
        return tokenArray(new StringTokenizer(s, delimiters));
    }

    // TODO: document better
    /*
     * Uses {@link StringTokenizer StringTokenizer}.
     */
    public static String[] tokenVector(String s) {
        return tokenArray(new StringTokenizer(s));
    }

    public static String tokenList(String[] list) {
        StringBuilder t = new StringBuilder();
        if (list.length > 0) {
            t.append(list[0]);
            for (int i = 1; i < list.length; i++) {
                t.append(" ").append(list[i]);
            }
        }

        return t.toString();
    }

    /*
     * Converts a set of characters represented as a string to a {@link BitSet BitSet}.
     * <p>The BitSet returned is suitable for use with 
     * {@link #checkAllowedChars(String, BitSet) checkAllowedChars()}.
     */
    public static BitSet charSet(String s) {
        BitSet set = new BitSet(128);

        for (int i = 0; i < s.length(); i++) {
            set.set(s.charAt(i));
        }

        return set;
    }

    private static int firstMember(String s, BitSet charSet, boolean invertSet, int startOffset) {
        for (int i = startOffset; i < s.length(); i++) {
            if (invertSet ^ charSet.get(s.charAt(i))) {
                return i;
            }
        }

        return -1;
    }

    /*
     * Check that no characters from <code><i>charSet</i></code> 
     * occur in <code><i>s</i></code>.
     * @return Index of first member character, -1 if there is none.
     */
    public static int firstMember(String s, BitSet charSet, int startOffset) {
        return firstMember(s, charSet, false, startOffset);
    }

    /*
     * Check that no characters from <code><i>charSet</i></code> 
     * occur in <code><i>s</i></code>.
     * @return Index of first member character, -1 if there is none.
     */
    public static int firstMember(String s, BitSet charSet) {
        return firstMember(s, charSet, 0);
    }

    /*
     * Check that no characters from <code><i>charSet</i></code> 
     * occur in <code><i>s</i></code>.
     * @return Index of first member character, -1 if there is none.
     */
    public static int firstMember(String s, String charSet) {
        return firstMember(s, charSet(charSet));
    }

    /*
     * Check that only characters from <code><i>charSet</i></code> 
     * occur in <code><i>s</i></code>.
     * @return Index of first non-member character, -1 if there is none.
     */
    public static int firstNonMember(String s, BitSet charSet, int startOffset) {
        return firstMember(s, charSet, true, startOffset);
    }

    /*
     * Check that only characters from <code><i>charSet</i></code> 
     * occur in <code><i>s</i></code>.
     * @return Index of first non-member character, -1 if there is none.
     */
    public static int firstNonMember(String s, BitSet charSet) {
        return firstNonMember(s, charSet, 0);
    }

    /*
     * Check that only characters from <code><i>charSet</i></code> 
     * occur in <code><i>s</i></code>.
     * @return Index of first non-member character, -1 if there is none.
     */
    public static int firstNonMember(String s, String charSet) {
        return firstNonMember(s, charSet(charSet));
    }

    /*
     * Check that only characters from <code><i>allowedChars</i></code> 
     * occur in <code><i>s</i></code>.
     * @return true iff there are only legal characters.
     */
    public static boolean hasOnlyLegalChars(String s, BitSet allowedChars) {
        return firstNonMember(s, allowedChars) == -1;
    }

    /*
     * Check that only characters from <code><i>allowedChars</i></code> 
     * occur in <code><i>s</i></code>.
     * @return true iff there are only legal characters.
     */
    public static boolean hasOnlyLegalChars(String s, String allowedChars) {
        return hasOnlyLegalChars(s, charSet(allowedChars));
    }

    /*
     * Check that only characters from <code><i>allowedChars</i></code> 
     * occur in <code><i>s</i></code>.
     * @throws IllegalArgumentException If an illegal character occurs
     */
    public static void checkAllowedChars(String s, BitSet allowedChars) {
        int i = firstNonMember(s, allowedChars);
        if (i != -1) {
            throw new IllegalArgumentException("Character '" + s.charAt(i) + "' not allowed.");
        }
    }

    /*
     * Check that only characters from <code><i>allowedChars</i></code> 
     * occur in <code><i>s</i></code>.
     * @throws IllegalArgumentException If an illegal character occurs
     */
    public static void checkAllowedChars(String s, String allowedChars) {
        checkAllowedChars(s, charSet(allowedChars));
    }

    /*
     * Tests if a string starts with a prefix and, if so, removes it.
     * @return The substring of <code><i>original</i><code> starting after <code><i>prefix</i><code>
     *         if it starts with <code><i>prefix</i><code>, null otherwise.
     */
    public static String checkRemovePrefix(String original, String prefix) {
        return original.startsWith(prefix) ? original.substring(prefix.length()) : null;
    }

    /*
     * Replace &quot;Java&quot; (C++) escapes.
     */
    public static String javaUnescape(String s) {
        StringBuilder r = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '\\') {
                if (i + 1 < s.length()) {
                    switch (s.charAt(i + 1)) {
                        case 'r':
                            r.append('\r');
                            break;
                        case 'n':
                            r.append('\n');
                            break;
                        case 't':
                            r.append('\t');
                            break;
                        case '\\':
                            r.append('\\');
                            break;
                        default:
                            throw new IllegalArgumentException("Malformed escape: " + s.substring(i, i + 2));
                    }
                    i++;
                } else {
                    throw new IllegalArgumentException("Malformed escape: " + s.charAt(i));
                }
            } else {
                r.append(s.charAt(i));
            }
        }

        return r.toString();
    }

    public static String padLeft(String s, int length, char padChar) {
        StringBuilder r = new StringBuilder(length);
        while (r.length() + s.length() < length) {
            r.append(padChar);
        }
        r.append(s);
        return r.toString();
    }

    public static String zeroPaddedNumber(int n, int length) {
        return padLeft(Integer.toString(n), length, '0');
    }

    // TODO: Upper/lowercase.
    public static String zeroPaddedHex(int n, int length) {
        return padLeft(Integer.toHexString(n), length, '0');
    }

    public static String zeroPaddedBinary(int n, int length) {
        return padLeft(Integer.toBinaryString(n), length, '0');
    }

    public static String[] readFile(File file) throws IOException {
        Vector<String> v = new Vector<String>();
        LineNumberReader r = new LineNumberReader(new FileReader(file));
        String t;
        while ((t = r.readLine()) != null) {
            v.addElement(t);
        }
        r.close();
        String[] s = new String[v.size()];
        v.copyInto(s);
        return s;
    }

    public static String[] readFile(String filename) throws IOException {
        return readFile(new File(filename));
    }

}
