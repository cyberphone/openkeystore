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
package org.webpki.webapps.csf_lab;

import java.io.IOException;

import java.math.BigInteger;

import java.util.ArrayList;

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORBoolean;
import org.webpki.cbor.CBORByteString;
import org.webpki.cbor.CBORFloatingPoint;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORNull;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORTag;
import org.webpki.cbor.CBORTextString;

/**
 * Class for converting diagnostic CBOR to CBOR.
 */
public class CBORDiagnosticParser {

    char[] cborDiagnostic;
    int index;
    boolean sequence;
    
    CBORDiagnosticParser(String cborDiagnostic, boolean sequence) {
        this.cborDiagnostic = cborDiagnostic.toCharArray();
        this.sequence = sequence;
    }
    
    /**
     * Parse Diagnostic CBOR to CBOR.
     * 
     * @param cborDiagnostic String holding diagnostic (textual) CBOR
     * @return CBORObject
     * @throws IOException
     */
    public static CBORObject parse(String cborDiagnostic) throws IOException {
        return new CBORDiagnosticParser(cborDiagnostic, false).readToEOF();
    }

    /**
     * Parse Diagnostic CBOR sequence to array of CBOR.
     * 
     * @param cborDiagnostic String holding diagnostic (textual) CBOR
     * @return CBORObject
     * @throws IOException
     */
    public static CBORObject[] parseSequence(String cborDiagnostic) throws IOException {
        return new CBORDiagnosticParser(cborDiagnostic, true).readSequenceToEOF();
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
                return new CBORByteString(embedded.encode());
    
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
       
            case '"':
                return getTextString();
                
            case 'h':
                return getByteString();
                
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
                if (nextChar() == 'I') {
                    scanFor("Infinity");
                    return new CBORFloatingPoint(Double.NEGATIVE_INFINITY);
                }

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

            case '+':
                return getNumberOrTag();

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

    private CBORObject getNumberOrTag() throws IOException {
        StringBuilder token = new StringBuilder();
        index--;
        char c;
        boolean floatingPoint = false;
        do  {
            token.append(readChar());
            c = nextChar();
            if (c == '.' || c == 'e' || c == 'E') {
                floatingPoint = true;
                c = '0';
            }
        } while ((c >= '0' && c <= '9') || c == '+'  || c == '-');
        String number = token.toString();
        try {
            if (floatingPoint) {
                Double value = Double.valueOf(number);
                // Implicit overflow is not permitted
                if (value.isInfinite()) {
                    reportError("Floating point value out of range");
                }
                return new CBORFloatingPoint(value);
            }
            if (c == '(') {
                // Do not accept '+', '-', or leading zeros
                if (number.charAt(0) < '0' || (number.charAt(0) == '0' && number.length() > 1)) {
                    reportError("Tag syntax error");
                }
                readChar();
                CBORTag cborTag = 
                        new CBORTag(Long.parseUnsignedLong(number), getObject());
                scanFor(")");
                return cborTag;
            }
            return new CBORInteger(new BigInteger(number));
        } catch (IllegalArgumentException e) {
            reportError(e.getMessage());
        }
        return null; // For the compiler...
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

    private CBORObject getTextString() throws IOException {
        StringBuilder s = new StringBuilder();
        while (true) {
            char c;
            switch (c = readChar()) {
                case '\\':
                    switch (c = readChar()) {
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
                    return new CBORTextString(s.toString());
                    
                default:
                    if (c < ' ') {
                        reportError(String.format("Unexpected control character: %s", toChar(c)));
                    }
            }
            s.append(c);
        }
    }
    
    private CBORObject getByteString() throws IOException {
        StringBuilder s = new StringBuilder();
        scanFor("'");
        char c;
        while ((c = readChar()) != '\'') {
            s.append(hexCharToChar(c));
        }
        String hex = s.toString();
        int l = hex.length();
        if ((l & 1) != 0) {
            reportError("Uneven number of hex characters");
        }
        byte[] bytes = new byte[l >> 1];
        int q = 0;
        int i = 0;
        while (q < l) {
            bytes[i++] = (byte)((hex.charAt(q++) << 4) + hex.charAt(q++));
        }
        return new CBORByteString(bytes);
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

                default:
                    return;
            }
        }
    }
}
