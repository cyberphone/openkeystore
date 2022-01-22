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

/**
 * Class for converting JSON to CBOR.
 */
public class CBORFromJSON {

    char[] json;
    int index;
    
    // 2^53 ("53-bit precision")
    static final long MAX_JSON_INTEGER = 9007199254740992l;

    CBORFromJSON(String jsonString) {
        this.json = jsonString.toCharArray();
    }
    
    /**
     * Convert JSON to CBOR.
     * 
     * Note: currently only integer numbers are supported.
     * 
     * @param jsonString
     * @return CBOR
     * @throws IOException
     */
    public static CBORObject convert(String jsonString) throws IOException {
        return new CBORFromJSON(jsonString).readToEOF();
    }

    private void syntaxError() throws IOException {
        throw new IOException("Syntax error around position: " + index);
    }
    
    private CBORObject readToEOF() throws IOException {
        CBORObject cborObject = getObject();
        if (index < json.length) {
            throw new IOException("Unexpected data after token");
        }
        return cborObject;
    }

    private CBORObject getObject() throws IOException {
        scanWhiteSpace();
        CBORObject cborObject = getRawObject();
        scanWhiteSpace();
        return cborObject;
    }
    
    private boolean continueList(char validStop) throws IOException {
        if (nextChar() == ',') {
            readChar();
            scanWhiteSpace();
            return true;
        }
        if (nextChar() != validStop) {
            syntaxError();
        }
        return false;
    }
    
    private CBORObject getRawObject() throws IOException {
        switch (readChar()) {
    
            case '[':
                CBORArray array = new CBORArray();
                scanWhiteSpace();
                while (readChar() != ']') {
                    index--;
                    do {
                        array.addObject(getObject());
                    } while (continueList(']'));
                }
                return array;
     
            case '{':
                CBORMap map = new CBORMap();
                scanWhiteSpace();
                while (readChar() != '}') {
                    index--;
                    do {
                        if (nextChar() != '"') {
                            syntaxError();
                        } 
                        CBORObject key = getObject();
                        if (readChar() != ':') {
                            syntaxError();
                        }
                        map.setObject(key, getObject());
                    } while (continueList('}'));
                }
                return map;
       
            case '"':
                return getString();
      
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
                readChar();
                return getInteger("-");
                
            default:
                return getInteger("");
        }
    }

    private CBORInteger getInteger(String initial) throws IOException {
        StringBuilder token = new StringBuilder(initial);
        index--;
        char c;
        do  {
            token.append(readChar());
        } while (((c = nextChar()) >= '0' && c <= '9') || c == '.');
        long value = Long.valueOf(token.toString());
        if (Math.abs(value) > MAX_JSON_INTEGER) {
            throw new IOException("JSON integer exceeded 2^53");
        }
        return new CBORInteger(value);
    }

    private char nextChar() throws IOException {
        if (index == json.length) return 0;
        char c = readChar();
        index--;
        return c;
    }

    private void scanFor(String string) throws IOException {
        for (char c : string.toCharArray()) {
            if (c != readChar()) {
                syntaxError();
            }
        }
    }

    private CBORTextString getString() throws IOException {
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
                            syntaxError();
                    }
                    break;
 
                case '"':
                    return new CBORTextString(s.toString());
                    
                default:
                    if (c < ' ') {
                        syntaxError();
                    }
            }
            s.append(c);
        }
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
        syntaxError();
        return 0; // For the compiler...
    }

    private char readChar() throws IOException {
        if (index >= json.length) {
            throw new IOException("EOF error");
        }
        return json[index++];
    }

    private void scanWhiteSpace() throws IOException {
        while (index < json.length) {
            switch (nextChar()) {
                case ' ':
                case '\n':
                case '\r':
                case '\t':
                    readChar();
                    continue;
                default:
                    return;
            }
        }
    }
}
