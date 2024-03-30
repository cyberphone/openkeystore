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
package org.webpki.util;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;

/**
 * Encodes/decodes UTF-8 data.
 */
public class UTF8 {
    
    private UTF8() {}  // No instantiation please

    static final CharsetDecoder Utf8Decoder;
    
    static {
        try {
            Utf8Decoder = Charset.forName("utf-8").newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static final CharsetEncoder Utf8Encoder;
    
    static {
        try {
            Utf8Encoder = Charset.forName("utf-8").newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encodes Java (UTF-16) String to UTF-8.
     * <p>
     * This method was added because <code>String.getBytes("utf-8")</code>  does
     * not flag invalid UTF-16.
     * </p>
     *
     * @param utf16String String presumably holding valid UTF-16
     * @return UTF-8 byte array
     * @throws IllegalArgumentException
     */
    public static byte[] encode(String utf16String) {
        try {
            ByteBuffer byteBuffer = Utf8Encoder.encode(CharBuffer.wrap(utf16String));
            byte[] utf8Bytes = new byte[byteBuffer.limit()];
            System.arraycopy(byteBuffer.array(), 0, utf8Bytes, 0, byteBuffer.limit());
            return utf8Bytes;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Decodes a UTF-8 byte array into a String.
     * <p>
     * This method was added because <code>new&nbsp;String(byteArray,&nbsp;"utf-8")</code>  does
     * not flag invalid UTF-8.
     * </p>
     *
     * @param utf8Bytes Binary data presumably holding valid UTF-8
     * @return Java (UTF-16) String
     * @throws IllegalArgumentException
     */
    public static String decode(byte[] utf8Bytes) {
        try {
            return Utf8Decoder.decode(ByteBuffer.wrap(utf8Bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
