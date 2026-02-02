/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
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

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for converting diagnostic notation CBOR to CBOR.
 * <p>
 * Note: generated CBOR always conform to 
 * <a href='package-summary.html#deterministic-encoding' class='webpkilink'>Deterministic&nbsp;Encoding</a>.
 * </p>
 */
public class CBORDiagnosticNotation {
    
    char[] cborText;
    int index;
    boolean sequenceFlag;
    
    CBORDiagnosticNotation(String cborText, boolean sequenceFlag) {
        this.cborText = cborText.toCharArray();
        this.sequenceFlag = sequenceFlag;
    }
    
    /**
     * Convert CBOR object in diagnostic notation, to CBOR.
     * <p>
     * This method can also be used for decoding JSON data.
     * </p>
     * 
     * @param cborText String holding a CBOR object in diagnostic (textual) format.
     * @return CBOR object
     * @throws CBORException
     */
    public static CBORObject convert(String cborText) {
        return new CBORDiagnosticNotation(cborText, false).readSequenceToEOF().get(0);
    }

    /**
     * Convert CBOR sequence in diagnostic notation to CBOR.
     * 
     * @param cborText String holding zero or more comma-separated CBOR objects in diagnostic (textual) format.
     * @return Array holding zero or more CBOR objects
     * @throws CBORException
     */
    public static ArrayList<CBORObject> convertSequence(String cborText) {
        return new CBORDiagnosticNotation(cborText, true).readSequenceToEOF();
    }

    private String buildError(String error) {
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
        return complete.append("^\n\nError in line ")
                       .append(lineNumber)
                       .append(". ")
                       .append(error).toString();
    }

    void parserError(String error) {
        throw new RuntimeException(error);
    }
    
    private ArrayList<CBORObject> readSequenceToEOF() {
        try {
            ArrayList<CBORObject> sequence = new ArrayList<>();
            scanNonSignficantData();
            while (index < cborText.length) {
                if (!sequence.isEmpty()) {
                    if (sequenceFlag) {
                        scanFor(",");
                    } else {
                        readChar();
                        parserError(CBORDecoder.STDERR_UNEXPECTED_DATA);
                    }
                }
                sequence.add(getObject());
            }
            if (sequence.isEmpty() && !sequenceFlag) {
                readChar();
            }
            return sequence;
        } catch (Exception e) {
            // Build message and convert to CBORException.
            throw new CBORException(buildError(e.getMessage()));
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
            return true;
        }
        char actual = readChar(); 
        if (validStop != actual) {
            parserError(String.format(
                "Expected: ',' or '%c' actual: %s", validStop, toReadableChar(actual)));
        }
        index--;
        return false;
    }
    
    private CBORObject getRawObject() {
        return switch (readChar()) {
        
            case '<' -> {
                scanFor("<");
                CBORArray sequence = new CBORArray();
                scanNonSignficantData();
                while (readChar() != '>') {
                    index--;
                    do {
                        sequence.add(getObject());
                    } while (continueList('>'));
                }
                scanFor(">");
                yield new CBORBytes(sequence.encodeAsSequence());
            }
    
            case '[' -> {
                CBORArray array = new CBORArray();
                scanNonSignficantData();
                while (readChar() != ']') {
                    index--;
                    do {
                        array.add(getObject());
                    } while (continueList(']'));
                }
                yield array;
            }
     
            case '{' -> {
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
                yield map;
            }
       
            case '\'' -> getString(true);
                
            case '"' -> getString(false);

            case 'h' -> getBytes(false);

            case 'b' -> {
                if (nextChar() == '3') {
                    scanFor("32'");
                    parserError("b32 not implemented");
                }
                scanFor("64");
                yield getBytes(true);
            }
                
            case 't' -> {
                scanFor("rue");
                yield new CBORBoolean(true);
            }
       
            case 'f' -> {
                if (nextChar() == 'a') {
                    scanFor("alse");
                    yield new CBORBoolean(false);
                }
                scanFor("loat");
                byte[] floatBytes = getBytes(false).getBytes();
                switch (floatBytes.length) {
                    case 2:
                    case 4:
                    case 8:
                    break;
                    default:
                        parserError("Argument must be a 16, 32, or 64-bit floating-point number");
                }
                yield new CBORDecoder(
                    CBORUtil.concatByteArrays(
                        new byte[]{(byte)(SIMPLE_FLOAT16 + (floatBytes.length >> 2))}, floatBytes),
                    CBORDecoder.LENIENT_NUMBER_DECODING).decodeWithOptions();
            }
       
            case 'n' -> {
                scanFor("ull");
                yield new CBORNull();
            }

            case 's' -> {
                scanFor("imple(");
                yield simpleType();
            }
                
            case '-' -> {
                if (readChar() == 'I') {
                    scanFor("nfinity");
                    yield new CBORNonFinite(0xfc00);
                }
                yield getNumberOrTag(true);
            }

            case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' -> getNumberOrTag(false);

            case 'N' -> {
                scanFor("aN");
                yield new CBORNonFinite(0x7e00);
            }

            case 'I' -> {
                scanFor("nfinity");
                yield new CBORNonFinite(0x7c00);
            }
                
            default -> {
                index--;
                parserError(String.format("Unexpected character: %s", toReadableChar(readChar())));
                yield null;  // For the compiler...
            }
        };
    }

    private CBORObject simpleType() {
        StringBuilder token = new StringBuilder();
        while (true)  {
            switch (nextChar()) {
                default:
                    token.append(readChar());
                    continue;

                case ')':
                    break;

                case '+':
                case '-':
                case 'e':
                case '.':
                    parserError("Syntax error");
            }
            break;
        }
        readChar();
        // Clone gives bool and null precedence over simple.
        return new CBORSimple(Integer.valueOf(token.toString().trim())).clone();
    }

    @SuppressWarnings("fallthrough")
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
                case 'e':
                    if (prefix == null) {
                        floatingPoint = true;
                    }
                    continue;

                case '_':
                    if (prefix == null) {
                        parserError("'_' is only permitted for 0b, 0o, and 0x numbers");
                    }
                    readChar();

                default:
                    continue;
            }
            break;
        }
        String number = token.toString();
        if (floatingPoint) {
            testForNonDecimal(prefix);
            Double value = Double.valueOf(number);
            // Implicit overflow is not permitted
            if (value.isInfinite()) {
                parserError("Floating point value out of range");
            }
            return new CBORFloat(negative ? -value : value);
        }
        if (nextChar() == '(') {
            // Do not accept '-', 0xhhh, or leading zeros
            testForNonDecimal(prefix);
            if (negative || (number.length() > 1 && number.charAt(0) == '0')) {
                parserError("Tag syntax error");
            }
            readChar();
            long tagNumber = Long.parseUnsignedLong(number);
            CBORTag cborTag = new CBORTag(tagNumber, getObject());
            scanFor(")");
            return cborTag;
        }
        BigInteger bigInteger = new BigInteger(number, prefix == null ? 10 : prefix);
        return new CBORInt(negative ? bigInteger.negate() : bigInteger);
    }

    private void testForNonDecimal(Integer nonDecimal) {
        if (nonDecimal != null) {
            parserError("0b, 0o, and 0x prefixes are only permited for integers");
        }
    }

    private char nextChar() {
        if (index == cborText.length) return 0;
        char c = readChar();
        index--;
        return c;
    }

    private String toReadableChar(char c) {
        return c < ' ' ? String.format("\\u%04x", (int) c) : String.format("'%c'", c);
    }

    private void scanFor(String expected) {
        for (char c : expected.toCharArray()) {
            char actual = readChar(); 
            if (c != actual) {
                parserError(String.format("Expected: '%c' actual: %s", c, toReadableChar(actual)));
            }
        }
    }

    private CBORObject getString(boolean byteString) {
        StringBuilder s = new StringBuilder();
        while (true) {
            char c;
            switch (c = readChar()) {
                // Special character handling.
                case '\r':
                    if (nextChar() == '\n') {
                        continue;  // CRLF => LF
                    }
                    c = '\n';  // Single CR => LF
                    break;

                case '\n':
                case '\t':
                    break;

                case '\\':
                    switch (c = readChar()) {
                        case '\n':
                            continue;  // Line continuation

                        // JSON compatible escape sequences
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
                            parserError(String.format("Invalid escape character %s", toReadableChar(c)));
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

                // Normal character handling
                default:
                    if (c < ' ') {
                        parserError(String.format("Unexpected control character: %s", toReadableChar(c)));
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
            parserError("Uneven number of hex characters");
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
        return (char) switch (c) {
            case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' -> c - '0';
            case 'a', 'b', 'c', 'd', 'e', 'f' -> c - 'a' + 10;
            case 'A', 'B', 'C', 'D', 'E', 'F' -> c - 'A' + 10;
            default -> {
                parserError(String.format("Bad hex character: %s", toReadableChar(c)));
                yield 0;  // For the compiler...
            }
        };
    }

    private char readChar() {
        if (index >= cborText.length) {
            parserError("Unexpected EOF");
        }
        return cborText[index++];
    }

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
                    while (readChar() != '/') {
                    }
                    continue;

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
