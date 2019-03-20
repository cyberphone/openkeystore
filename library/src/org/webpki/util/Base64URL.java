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

import java.io.IOException;

import org.webpki.crypto.CryptoRandom;

/**
 * Encodes/decodes base64URL data.
 * See RFC 4648 Table 2.
 */
public class Base64URL {

    public final static char[] BASE64URL = {
    //   0   1   2   3   4   5   6   7
        'A','B','C','D','E','F','G','H', // 0
        'I','J','K','L','M','N','O','P', // 1
        'Q','R','S','T','U','V','W','X', // 2
        'Y','Z','a','b','c','d','e','f', // 3
        'g','h','i','j','k','l','m','n', // 4
        'o','p','q','r','s','t','u','v', // 5
        'w','x','y','z','0','1','2','3', // 6
        '4','5','6','7','8','9','-','_'  // 7
    };
    
    final static byte[] DECODE_TABLE = {
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, 62, -1, -1,
        52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6, 
         7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, -1, -1, -1, -1, 63,
        -1, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51
    };

    private Base64URL() {}  // No instantiation please

    /**
     * Converts a base64url encoded String to a byte array.<p>
     * For every 4 base64url characters you'll get 3 binary bytes.</p>
     *
     * @param base64url Encoded data
     * @return Decoded data as a byte array
     * @throws IOException If input data isn't valid base64url data
     */
    public static byte[] decode(String base64url) throws IOException {
        byte[] encoded = base64url.getBytes("UTF-8");
        byte[] semidecoded = new byte[encoded.length];
        for (int i = 0; i < encoded.length; i++) {
            byte c = encoded[i];
            if (c < 0 || c >= DECODE_TABLE.length || (c = DECODE_TABLE[c]) < 0) {
                throw new IOException("bad character at index " + i);
            }
            semidecoded[i] = c;
        }
        int decoded_length = (encoded.length / 4) * 3;
        int encoded_length_modulo_4 = encoded.length % 4;
        if (encoded_length_modulo_4 != 0) {
            decoded_length += encoded_length_modulo_4 - 1;
        }
        byte[] decoded = new byte[decoded_length];
        int decoded_length_modulo_3 = decoded.length % 3;
        if (decoded_length_modulo_3 == 0 && encoded_length_modulo_4 != 0) {
            throw new IOException("Wrong number of Base64URL characters");
        }

        // -----:  D E C O D E :-----
        int i = 0, j = 0;
        //decode in groups of four bytes
        while (j < decoded.length - decoded_length_modulo_3) {
            decoded[j++] = (byte) ((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            decoded[j++] = (byte) ((semidecoded[i++] << 4) | (semidecoded[i] >>> 2));
            decoded[j++] = (byte) ((semidecoded[i++] << 6) | semidecoded[i++]);
        }
        //decode "odd" bytes
        if (decoded_length_modulo_3 == 1) {
            decoded[j] = (byte) ((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            if ((semidecoded[i] & 0x0F) != 0) {
                throw new IOException("Wrong termination character");
            }
        } else if (decoded_length_modulo_3 == 2) {
            decoded[j++] = (byte) ((semidecoded[i++] << 2) | (semidecoded[i] >>> 4));
            decoded[j] = (byte) ((semidecoded[i++] << 4) | (semidecoded[i] >>> 2));
            if ((semidecoded[i] & 0x03) != 0) {
                throw new IOException("Wrong termination character");
            }
        }
        return decoded;
    }

    /**
     * Converts a byte array to a base64url encoded String.<p>
     * For every 3 binary bytes, you'll get 4 base64url characters.</p>
     *
     * @param byteArray Binary data
     * @return Encoded data as a String
     * @throws IOException &nbsp;
     */
    public static String encode(byte[] byteArray) throws IOException {
        //determine length of output
        int i;
        int modulo3 = byteArray.length % 3;
        //(1)
        i = (byteArray.length / 3) * 4;
        //(2)
        if (modulo3 != 0) {
            i += modulo3 + 1;
        }
        //(3)
        char[] encoded = new char[i];
        i = 0;
        int j = 0;
        //encode by threes
        while (j < byteArray.length - modulo3) {
            encoded[i++] = BASE64URL[(byteArray[j] >>> 2) & 0x3F];
            encoded[i++] = BASE64URL[((byteArray[j++] << 4) & 0x30) | ((byteArray[j] >>> 4) & 0x0F)];
            encoded[i++] = BASE64URL[((byteArray[j++] << 2) & 0x3C) | ((byteArray[j] >>> 6) & 0x03)];
            encoded[i++] = BASE64URL[byteArray[j++] & 0x3F];
        }
        //encode  "odd" bytes
        if (modulo3 == 1) {
            encoded[i++] = BASE64URL[(byteArray[j] >>> 2) & 0x3F];
            encoded[i]   = BASE64URL[(byteArray[j] << 4) & 0x30];
        } else if (modulo3 == 2) {
            encoded[i++] = BASE64URL[(byteArray[j] >>> 2) & 0x3F];
            encoded[i++] = BASE64URL[((byteArray[j++] << 4) & 0x30) | ((byteArray[j] >>> 4) & 0x0F)];
            encoded[i]   = BASE64URL[(byteArray[j] << 2) & 0x3C];
        }
        return new String(encoded);
    }

    /**
     * Generates a base64url encoded nonce.
     * @param length Number of characters
     * @return Encoded nonce
     */
    public static String generateURLFriendlyRandom(int length) {
        byte[] random = CryptoRandom.generateRandom(length);
        StringBuilder buffer = new StringBuilder();
        for (int i = 0; i < length; i++) {
            buffer.append(BASE64URL[random[i] & 0x3F]);
        }
        return buffer.toString();
    }
}
