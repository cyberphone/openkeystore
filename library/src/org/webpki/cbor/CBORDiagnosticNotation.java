/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
package org.webpki.cbor;

import java.math.BigInteger;

import java.util.ArrayList;

import org.webpki.util.Base64URL;
import org.webpki.util.UTF8;

/**
 * Class for converting diagnostic CBOR to CBOR.
 */
public class CBORDiagnosticNotation {

    char[] cborText;
    int index;
    boolean sequence;
    
    CBORDiagnosticNotation(String cborText, boolean sequence) {
        this.cborText = cborText.toCharArray();
        this.sequence = sequence;
    }
    
    /**
     * Decodes diagnostic notation CBOR to CBOR.
     * 
     * @param cborText String holding diagnostic (textual) CBOR
     * @return {@link CBORObject}
     */
    public static CBORObject decode(String cborText) {
        return new CBORDiagnosticNotation(cborText, false).readToEOF();
    }

    /**
     * Decodes diagnostic notation CBOR sequence to CBOR.
     * 
     * @param cborText String holding diagnostic (textual) CBOR
     * @return {@link CBORObject}[] Non-empty array of CBOR objects
     */
    public static CBORObject[] decodeSequence(String cborText) {
        return new CBORDiagnosticNotation(cborText, true).readSequenceToEOF();
    }

    private void reportError(String error) {
        // Unsurprisingly, error handling turned out to be the most complex part...
        int start = index - 100;
        if (start < 0) {
            start = 0;
        }
        int linePos = 0;
        while (start < index - 1) {
            if (cborText[start++] == '\n') {
                linePos = start;
            }
        }
        StringBuilder complete = new StringBuilder();
        if (index > 0 && cborText[index - 1] == '\n') {
            index--;
        }
        int endLine = index;
        while (endLine < cborText.length) {
            if (cborText[endLine] == '\n') {
                break;
            }
            endLine++;
        }
        for (int q = linePos; q < endLine; q++) {
            complete.append(cborText[q]);
        }
        complete.append('\n');
        for (int q = linePos; q < index; q++) {
            complete.append('-');
        }
        int lineNumber = 1;
        for (int q = 0; q < index - 1; q++) {
            if (cborText[q] == '\n') {
                lineNumber++;
            }
        }
        throw new CBORException(complete.append("^\n\nError in line ")
                                        .append(lineNumber)
                                        .append(". ")
                                        .append(error).toString());
    }
    
    private CBORObject readToEOF() {
        CBORObject cborObject = getObject();
        if (index < cborText.length) {
            readChar();
            reportError("Unexpected data after token");
        }
        return cborObject;
    }

    private CBORObject[] readSequenceToEOF() {
        ArrayList<CBORObject> sequence = new ArrayList<>();
        while (true) {
            sequence.add(getObject());
            if (index < cborText.length) {
                scanFor(",");
            } else {
                return sequence.toArray(new CBORObject[0]);
            }
        }
    }

    private CBORObject getObject() {
        scanNonSignficantData();
        CBORObject cborObject = getRawObject();
        scanNonSignficantData();
        return cborObject;
    }
    
    private boolean continueList(char validStop) {
        if (nextChar() == ',') {
            readChar();
            scanNonSignficantData();
            return true;
        }
        scanFor(String.valueOf(validStop));
        index--;
        return false;
    }
    
    private CBORObject getRawObject() {
        switch (readChar()) {
        
            case '<':
                scanFor("<");
                CBORObject embedded = getObject();
                scanFor(">>");
                return new CBORBytes(embedded.encode());
    
            case '[':
                CBORArray array = new CBORArray();
                scanNonSignficantData();
                while (readChar() != ']') {
                    index--;
                    do {
                        array.add(getObject());
                    } while (continueList(']'));
                }
                return array;
     
            case '{':
                CBORMap map = new CBORMap();
                scanNonSignficantData();
                while (readChar() != '}') {
                    index--;
                    do {
                        CBORObject key = getObject();
                        scanFor(":");
                        map.set(key, getObject());
                    } while (continueList('}'));
                }
                return map;
       
            case '\'':
                return getString(true);
                
            case '"':
                return getString(false);

            case 'h':
                return getBytes(false);

            case 'b':
                if (nextChar() == '3') {
                    scanFor("32'");
                    reportError("b32 not implemented");
                }
                scanFor("64");
                return getBytes(true);
                
            case 't':
                scanFor("rue");
                return new CBORBool(true);
       
            case 'f':
                scanFor("alse");
                return new CBORBool(false);
       
            case 'n':
                scanFor("ull");
                return new CBORNull();

            case '-':
                if (readChar() == 'I') {
                    scanFor("nfinity");
                    return new CBORFloat(Double.NEGATIVE_INFINITY);
                }
                return getNumberOrTag(true);

            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
               return getNumberOrTag(false);

            case 'N':
                scanFor("aN");
                return new CBORFloat(Double.NaN);

            case 'I':
                scanFor("nfinity");
                return new CBORFloat(Double.POSITIVE_INFINITY);
                
            default:
                index--;
                reportError(String.format("Unexpected character: %s", toChar(readChar())));
                return null;  // For the compiler...
        }
    }

    private CBORObject getNumberOrTag(boolean negative) {
        StringBuilder token = new StringBuilder();
        index--;
        Integer prefix = null;
        if (readChar() == '0') {
            switch (nextChar()) {
                case 'b':
                    prefix = 2;
                    break;
                
                case 'o':
                    prefix = 8;
                    break;
                
                case 'x':
                    prefix = 16;
                    break;
            }
        }
        if (prefix == null) {
            index--;
        } else {
            readChar();
        }
        boolean floatingPoint = false;
        while (true)  {
            token.append(readChar());
            switch (nextChar()) {
                case 0:
                case ' ':
                case '\n':
                case '\r':
                case '\t':
                case ',':
                case ':':
                case '>':
                case ']':
                case '}':
                case '/':
                case '#':
                case '(':
                case ')':
                    break;
                    
                case '.':
                    floatingPoint = true;
                    continue;

                default:
                    continue;
            }
            break;
        }
        String number = token.toString();
        try {
            if (floatingPoint) {
                testForNonDecimal(prefix);
                Double value = Double.valueOf(number);
                // Implicit overflow is not permitted
                if (value.isInfinite()) {
                    reportError("Floating point value out of range");
                }
                return new CBORFloat(negative ? -value : value);
            }
            if (nextChar() == '(') {
                // Do not accept '-', 0xhhh, or leading zeros
                testForNonDecimal(prefix);
                if (negative || (number.length() > 1 && number.charAt(0) == '0')) {
                    reportError("Tag syntax error");
                }
                readChar();
                long tagNumber = Long.parseUnsignedLong(number);
                CBORObject taggedObject = getObject();
                if (tagNumber == CBORTag.RESERVED_TAG_COTX) {
                    CBORArray array;
                    if (taggedObject.getType() != CBORTypes.ARRAY ||
                        (array = taggedObject.getArray()).size() != 2 ||
                        (array.get(0).getType() != CBORTypes.TEXT_STRING)) {
                        reportError("Special tag " + CBORTag.RESERVED_TAG_COTX + " syntax error");
                    }
                }
                CBORTag cborTag = new CBORTag(tagNumber, taggedObject);
                scanFor(")");
                return cborTag;
            }
            BigInteger bigInteger = new BigInteger(number, prefix == null ? 10 : prefix);
            // Clone: slight quirk to get the proper CBOR integer type  
            return new CBORBigInt(negative ? bigInteger.negate() : bigInteger).clone();
        } catch (IllegalArgumentException e) {
            reportError(e.getMessage());
        }
        return null; // For the compiler...
    }

    private void testForNonDecimal(Integer nonDecimal) {
        if (nonDecimal != null) {
            reportError("Hexadecimal not permitted here");
        }
    }

    private char nextChar() {
        if (index == cborText.length) return 0;
        char c = readChar();
        index--;
        return c;
    }

    private String toChar(char c) {
        return c < ' ' ? String.format("\\u%04x", (int) c) : String.format("'%c'", c);
    }

    private void scanFor(String expected) {
        for (char c : expected.toCharArray()) {
            char actual = readChar(); 
            if (c != actual) {
                reportError(String.format("Expected: '%c' actual: %s", c, toChar(actual)));
            }
        }
    }

    private CBORObject getString(boolean byteString) {
        StringBuilder s = new StringBuilder();
        while (true) {
            char c;
            switch (c = readChar()) {
                // Multiline extension
                case '\n':
                case '\r':
                case '\t':
                    break;

                case '\\':
                    switch (c = readChar()) {
                        case '\n':
                            continue;

                        case '\'':
                        case '"':
                        case '\\':
                            break;
    
                        case 'b':
                            c = '\b';
                            break;
    
                        case 'f':
                            c = '\f';
                            break;
    
                        case 'n':
                            c = '\n';
                            break;
    
                        case 'r':
                            c = '\r';
                            break;
    
                        case 't':
                            c = '\t';
                            break;
    
                        case 'u':
                            c = 0;
                            for (int i = 0; i < 4; i++) {
                                c = (char) ((c << 4) + hexCharToChar(readChar()));
                            }
                            break;
    
                        default:
                            reportError(String.format("Invalid escape character %s", toChar(c)));
                    }
                    break;
 
                case '"':
                    if (!byteString) {
                        String test = s.toString();
                        UTF8.encode(test);
                        return new CBORString(test);
                    }
                    break;

                case '\'':
                    if (byteString) {
                        return new CBORBytes(UTF8.encode(s.toString()));
                    }
                    break;
                    
                default:
                    if (c < ' ') {
                        reportError(String.format("Unexpected control character: %s", toChar(c)));
                    }
            }
            s.append(c);
        }
    }
    
    private CBORObject getBytes(boolean b64) {
        StringBuilder s = new StringBuilder();
        scanFor("'");
        while(true) {
            char c;
            switch (c = readChar()) {
                case '\'':
                    break;
               
                case ' ':
                case '\r':
                case '\n':
                case '\t':
                    continue;

                default:
                    s.append(b64 ? c : hexCharToChar(c));
                    continue;
            }
            break;
        }
        String encoded = s.toString();
        if (b64) {
            return new CBORBytes(
                    Base64URL.decodePadded(encoded.replace('+', '-').replace('/', '_')));
        }
        int length = encoded.length();
        if ((length & 1) != 0) {
            reportError("Uneven number of hex characters");
        }
        byte[] bytes = new byte[length >> 1];
        int q = 0;
        int i = 0;
        while (q < length) {
            bytes[i++] = (byte)((encoded.charAt(q++) << 4) + encoded.charAt(q++));
        }
        return new CBORBytes(bytes);
    }

    private char hexCharToChar(char c) {
        if (c >= '0' && c <= '9') {
            return (char) (c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return (char) (c - 'a' + 10);
        }
        if (c >= 'A' && c <= 'F') {
            return (char) (c - 'A' + 10);
        }
        reportError(String.format("Bad hex character: %s", toChar(c)));
        return 0; // For the compiler...
    }

    private char readChar() {
        if (index >= cborText.length) {
            reportError("Unexpected EOF");
        }
        return cborText[index++];
    }

    @SuppressWarnings("fallthrough")
    private void scanNonSignficantData() {
        while (index < cborText.length) {
            switch (nextChar()) {
                case ' ':
                case '\n':
                case '\r':
                case '\t':
                    readChar();
                    continue;

                case '/':
                    readChar();
                    if (nextChar() != '/') {
                        while (readChar() != '/') {
                        }
                        continue;
                    }
                // Yes, '//' is currently considered as equivalent to '#'
                case '#':
                    readChar();
                    while (index < cborText.length && readChar() != '\n') {
                    }
                    continue;

                default:
                    return;
            }
        }
    }
}