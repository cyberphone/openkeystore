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

import java.io.IOException;

import java.math.BigInteger;

import java.util.ArrayList;

import org.webpki.util.Base64URL;

/**
 * Class for converting diagnostic CBOR to CBOR.
 */
public class CBORDiagnosticNotationDecoder {

    char[] cborDiagnostic;
    int index;
    boolean sequence;
    
    CBORDiagnosticNotationDecoder(String cborDiagnostic, boolean sequence) {
        this.cborDiagnostic = cborDiagnostic.toCharArray();
        this.sequence = sequence;
    }
    
    /**
     * Decodes diagnostic notation CBOR to CBOR.
     * 
     * @param cborDiagnostic String holding diagnostic (textual) CBOR
     * @return {@link CBORObject}
     * @throws IOException
     */
    public static CBORObject decode(String cborDiagnostic) throws IOException {
        return new CBORDiagnosticNotationDecoder(cborDiagnostic, false).readToEOF();
    }

    /**
     * Decodes diagnostic notation CBOR sequence to CBOR.
     * 
     * @param cborDiagnostic String holding diagnostic (textual) CBOR
     * @return {@link CBORObject}[] Non-empty array of CBOR objects
     * @throws IOException
     */
    public static CBORObject[] decodeSequence(String cborDiagnostic) throws IOException {
        return new CBORDiagnosticNotationDecoder(cborDiagnostic, true).readSequenceToEOF();
    }

    private void reportError(String error) throws IOException {
        // Unsurprisingly, error handling turned out to be the most complex part...
        int start = index - 100;
        if (start < 0) {
            start = 0;
        }
        int linePos = 0;
        while (start < index - 1) {
            if (cborDiagnostic[start++] == '\n') {
                linePos = start;
            }
        }
        StringBuilder complete = new StringBuilder();
        if (index > 0 && cborDiagnostic[index - 1] == '\n') {
            index--;
        }
        int endLine = index;
        while (endLine < cborDiagnostic.length) {
            if (cborDiagnostic[endLine] == '\n') {
                break;
            }
            endLine++;
        }
        for (int q = linePos; q < endLine; q++) {
            complete.append(cborDiagnostic[q]);
        }
        complete.append('\n');
        for (int q = linePos; q < index; q++) {
            complete.append('-');
        }
        int lineNumber = 1;
        for (int q = 0; q < index - 1; q++) {
            if (cborDiagnostic[q] == '\n') {
                lineNumber++;
            }
        }
        throw new IOException(complete.append("^\n\nError in line ")
                                      .append(lineNumber)
                                      .append(". ")
                                      .append(error).toString());
    }
    
    private CBORObject readToEOF() throws IOException {
        CBORObject cborObject = getObject();
        if (index < cborDiagnostic.length) {
            readChar();
            reportError("Unexpected data after token");
        }
        return cborObject;
    }

    private CBORObject[] readSequenceToEOF() throws IOException {
        ArrayList<CBORObject> sequence = new ArrayList<>();
        while (true) {
            sequence.add(getObject());
            if (index < cborDiagnostic.length) {
                scanFor(",");
            } else {
                return sequence.toArray(new CBORObject[0]);
            }
        }
    }

    private CBORObject getObject() throws IOException {
        scanNonSignficantData();
        CBORObject cborObject = getRawObject();
        scanNonSignficantData();
        return cborObject;
    }
    
    private boolean continueList(char validStop) throws IOException {
        if (nextChar() == ',') {
            readChar();
            scanNonSignficantData();
            return true;
        }
        scanFor(String.valueOf(validStop));
        index--;
        return false;
    }
    
    private CBORObject getRawObject() throws IOException {
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
                        array.addObject(getObject());
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
                        map.setObject(key, getObject());
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
                return new CBORBoolean(true);
       
            case 'f':
                scanFor("alse");
                return new CBORBoolean(false);
       
            case 'n':
                scanFor("ull");
                return new CBORNull();

            case '-':
                if (readChar() == 'I') {
                    scanFor("nfinity");
                    return new CBORFloatingPoint(Double.NEGATIVE_INFINITY);
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
                return new CBORFloatingPoint(Double.NaN);

            case 'I':
                scanFor("nfinity");
                return new CBORFloatingPoint(Double.POSITIVE_INFINITY);
                
            default:
                index--;
                reportError(String.format("Unexpected character: %s", toChar(readChar())));
                return null;  // For the compiler...
        }
    }

    private CBORObject getNumberOrTag(boolean negative) throws IOException {
        StringBuilder token = new StringBuilder();
        index--;
        boolean hexFlag = false;
        if (readChar() == '0') {
            if (nextChar() == 'x') {
                hexFlag = true;
                readChar();
            }
        }
        if (!hexFlag) {
            index--;
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
                testForHex(hexFlag);
                Double value = Double.valueOf(number);
                // Implicit overflow is not permitted
                if (value.isInfinite()) {
                    reportError("Floating point value out of range");
                }
                return new CBORFloatingPoint(negative ? -value : value);
            }
            if (nextChar() == '(') {
                // Do not accept '-', 0xhhh, or leading zeros
                testForHex(hexFlag);
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
                        (array.getObject(0).getType() != CBORTypes.TEXT_STRING)) {
                        reportError("Special tag " + CBORTag.RESERVED_TAG_COTX + " syntax error");
                    }
                }
                CBORTag cborTag = new CBORTag(tagNumber, taggedObject);
                scanFor(")");
                return cborTag;
            }
            BigInteger bigInteger = new BigInteger(number, hexFlag ? 16 : 10);
            // Slight quirk to get the proper CBOR integer type  
            return CBORObject.decode(new CBORBigInteger(negative ? 
                                             bigInteger.negate() : bigInteger).encode());
        } catch (IllegalArgumentException e) {
            reportError(e.getMessage());
        }
        return null; // For the compiler...
    }

    private void testForHex(boolean hexFlag) throws IOException {
        if (hexFlag) {
            reportError("Hexadecimal not permitted here");
        }
    }

    private char nextChar() throws IOException {
        if (index == cborDiagnostic.length) return 0;
        char c = readChar();
        index--;
        return c;
    }

    private String toChar(char c) {
        return c < ' ' ? String.format("\\u%04x", (int) c) : String.format("'%c'", c);
    }

    private void scanFor(String expected) throws IOException {
        for (char c : expected.toCharArray()) {
            char actual = readChar(); 
            if (c != actual) {
                reportError(String.format("Expected: '%c' actual: %s", c, toChar(actual)));
            }
        }
    }

    private CBORObject getString(boolean byteString) throws IOException {
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
                        return new CBORString(s.toString());
                    }
                    break;

                case '\'':
                    if (byteString) {
                        return new CBORBytes(s.toString().getBytes("utf-8"));
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
    
    private CBORObject getBytes(boolean b64) throws IOException {
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

    private char hexCharToChar(char c) throws IOException {
        switch (c) {
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
                return (char) (c - '0');
    
            case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                return (char) (c - 'a' + 10);
    
            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                return (char) (c - 'A' + 10);
        }
        reportError(String.format("Bad hex character: %s", toChar(c)));
        return 0; // For the compiler...
    }

    private char readChar() throws IOException {
        if (index >= cborDiagnostic.length) {
            reportError("Unexpected EOF");
        }
        return cborDiagnostic[index++];
    }

    private void scanNonSignficantData() throws IOException {
        while (index < cborDiagnostic.length) {
            switch (nextChar()) {
                case ' ':
                case '\n':
                case '\r':
                case '\t':
                    readChar();
                    continue;

                case '/':
                    readChar();
                    while (readChar() != '/') {
                    }
                    continue;
                    
                case '#':
                    readChar();
                    while (index < cborDiagnostic.length && readChar() != '\n') {
                    }
                    continue;

                default:
                    return;
            }
        }
    }
}
