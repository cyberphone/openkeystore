/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.jsf_lab;

import java.io.IOException;

import java.util.Vector;

/**
 * Parses JSON string/byte array data.
 */
public class JSONTokenExtractor {

    static final char LEFT_CURLY_BRACKET  = '{';
    static final char RIGHT_CURLY_BRACKET = '}';
    static final char DOUBLE_QUOTE        = '"';
    static final char COLON_CHARACTER     = ':';
    static final char LEFT_BRACKET        = '[';
    static final char RIGHT_BRACKET       = ']';
    static final char COMMA_CHARACTER     = ',';
    static final char BACK_SLASH          = '\\';

    int index;

    int maxLength;

    String jsonData;
    
    Vector<String> tokens;
    
    JSONTokenExtractor() {
        tokens = new Vector<String>();
    }

    Vector<String> getTokens(String jsonString) throws IOException {
        jsonData = jsonString;
        maxLength = jsonData.length();
        scanFor(LEFT_CURLY_BRACKET);
        scanObject();
        return tokens;
    }


    void scanElement() throws IOException {
        switch (scan()) {
            case LEFT_CURLY_BRACKET:
                scanObject();
                break;

            case DOUBLE_QUOTE:
                scanQuotedString();
                break;

            case LEFT_BRACKET:
                scanArray();
                break;

            default:
                scanSimpleType();
        }
    }

    void scanObject() throws IOException {
        boolean next = false;
        while (testNextNonWhiteSpaceChar() != RIGHT_CURLY_BRACKET) {
            if (next) {
                scanFor(COMMA_CHARACTER);
            }
            next = true;
            scanFor(DOUBLE_QUOTE);
            scanQuotedString();
            scanFor(COLON_CHARACTER);
            scanElement();
        }
        scan();
    }

    void scanArray() throws IOException {
        boolean next = false;
        while (testNextNonWhiteSpaceChar() != RIGHT_BRACKET) {
            if (next) {
                scanFor(COMMA_CHARACTER);
            } else {
                next = true;
            }
            scanElement();
        }
        scan();
    }

    void scanSimpleType() throws IOException {
        index--;
        StringBuilder tempBuffer = new StringBuilder();
        char c;
        while ((c = testNextNonWhiteSpaceChar()) != COMMA_CHARACTER && c != RIGHT_BRACKET && c != RIGHT_CURLY_BRACKET) {
            if (isWhiteSpace(c = nextChar())) {
                break;
            }
            tempBuffer.append(c);
        }
        tokens.add(tempBuffer.toString());
    }

    void scanQuotedString() throws IOException {
        StringBuilder result = new StringBuilder();
        while (true) {
            char c = nextChar();
            if (c == DOUBLE_QUOTE) {
                break;
            }
            if (c == BACK_SLASH) {
                result.append(BACK_SLASH);
                result.append(nextChar());
            } else {
                switch (c) {
                    case '&':
                        result.append("&amp;");
                        break;
                    case '>':
                        result.append("&gt;");
                        break;
                    case '<':
                        result.append("&lt;");
                        break;
                    default:
                        result.append(c);
                }
            }
        }
        tokens.add(result.toString());
    }

    char testNextNonWhiteSpaceChar() throws IOException {
        int save = index;
        char c = scan();
        index = save;
        return c;
    }

    void scanFor(char expected) throws IOException {
        char c = scan();
        if (c != expected) {
            throw new IOException("Expected '" + expected + "' but got '" + c + "'");
        }
    }

    char nextChar() throws IOException {
        if (index < maxLength) {
            return jsonData.charAt(index++);
        }
        throw new IOException("Unexpected EOF reached");
    }

    boolean isWhiteSpace(char c) {
        return c == 0x20 || c == 0x0A || c == 0x0D || c == 0x09;
    }

    char scan() throws IOException {
        while (true) {
            char c = nextChar();
            if (isWhiteSpace(c)) {
                continue;
            }
            return c;
        }
    }
}
