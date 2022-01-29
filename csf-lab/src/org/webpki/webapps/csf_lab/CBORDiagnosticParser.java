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

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORBoolean;
import org.webpki.cbor.CBORByteString;
import org.webpki.cbor.CBORFloatingPoint;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORNull;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORTextString;

import org.webpki.util.DebugFormatter;

/**
 * Class for converting diagnostic CBOR to CBOR.
 */
public class CBORDiagnosticParser {

    char[] cborDiagnostic;
    int index;
    
    CBORDiagnosticParser(String cborDiagnostic) {
        this.cborDiagnostic = cborDiagnostic.toCharArray();
    }
    
    /**
     * Parse Diagnostic CBOR to CBOR.
     * 
     * Note: currently only integer numbers are supported.
     * 
     * @param cborDiagnosticString
     * @return CBOR
     * @throws IOException
     */
    public static CBORObject parse(String cborDiagnostic) throws IOException {
        return new CBORDiagnosticParser(cborDiagnostic).readToEOF();
    }

    private void syntaxError(String error) throws IOException {
        throw new IOException(error);
    }
    
    private CBORObject readToEOF() throws IOException {
        CBORObject cborObject = getObject();
        if (index < cborDiagnostic.length) {
            throw new IOException("Unexpected data after token");
        }
        return cborObject;
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
                return getNumber();
                
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
                return getNumber();

            case 'N':
                scanFor("aN");
                return new CBORFloatingPoint(Double.NaN);

            case 'I':
                scanFor("nfinity");
                return new CBORFloatingPoint(Double.POSITIVE_INFINITY);
                
            default:
                index--;
                syntaxError(String.format("Unexpected character: %s", toChar(readChar())));
                return null;
        }
    }

    private CBORObject getNumber() throws IOException {
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
        return floatingPoint ? 
                new CBORFloatingPoint(Double.valueOf(token.toString())) 
                             : 
                new CBORInteger(new BigInteger(token.toString()));
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

    private void scanFor(String string) throws IOException {
        for (char c : string.toCharArray()) {
            char actual = readChar(); 
            if (c != actual) {
                syntaxError(String.format("Expected: '%c' actual: %s", c, toChar(actual)));
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
                                c = (char) ((c << 4) + getHexChar());
                            }
                            break;
    
                        default:
                            syntaxError(String.format("Invalid escape character %s", toChar(c)));
                    }
                    break;
 
                case '"':
                    return new CBORTextString(s.toString());
                    
                default:
                    if (c < ' ') {
                        syntaxError(String.format("Unexpected control character: %s", toChar(c)));
                    }
            }
            s.append(c);
        }
    }
    
    CBORObject getByteString() throws IOException {
        StringBuilder s = new StringBuilder();
        scanFor("'");
        char c;
        while ((c = readChar()) != '\'') {
            s.append(c);
        }
        String hex = s.toString();
        return new CBORByteString(hex.length() == 0 ? 
                                        new byte[0] : DebugFormatter.getByteArrayFromHex(hex));
    }

    private char getHexChar() throws IOException {
        char c;
        switch (c = readChar()) {
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
                return (char) (c - '0');

            case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                return (char) (c - 'a' + 10);

            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                return (char) (c - 'A' + 10);
        }
        syntaxError(String.format("Bad hex character: %s", toChar(c)));
        return 0; // For the compiler...
    }

    private char readChar() throws IOException {
        if (index >= cborDiagnostic.length) {
            throw new IOException("EOF error");
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
