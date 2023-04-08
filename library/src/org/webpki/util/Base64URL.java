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
package org.webpki.util;

// Source configured for JDK.

/**
 * Encodes/decodes base64URL data.
 * See RFC 4648 Table 2.
 */
public class Base64URL {

    private static final java.util.Base64.Encoder ENCODER = 
            java.util.Base64.getUrlEncoder().withoutPadding();

    private static final java.util.Base64.Decoder DECODER = 
            java.util.Base64.getUrlDecoder();

    private Base64URL() {}  // No instantiation please

    /**
     * Decodes base64url String to a byte array.
     * <p>
     * This method <b>does not</b> accept padding or line wraps.
     * </p>
     *
     * @param base64Url Encoded data
     * @return Decoded data as a byte array
     */
    public static byte[] decode(String base64Url) {
        if (base64Url.contains("=")) {
            throw new IllegalArgumentException("Padding not allowed");
        }
        // Flaky decoder fix :(
        return decodePadded(base64Url);
     }

    /**
     * Decodes a base64url String to a byte array.
     * <p>
     * This method accepts <i>optional</i> padding.
     * </p>
     * <p>
     * Note that line wraps are <b>not</b> permitted.
     * </p>
     * 
     * @param base64Url Encoded data
     * @return Decoded data as a byte array
     */
    public static byte[] decodePadded(String base64Url) {
        byte[] bytes = DECODER.decode(base64Url);
        // Flaky decoder fix :(
        final String reencoded = encode(bytes);
        int last = reencoded.length() - 1;
        if (reencoded.charAt(last) != base64Url.charAt(last)) {
                throw new IllegalArgumentException("Invalid base64 termination character");
        }
        return bytes;
    }

    /**
     * Encodes a byte array to a base64url String.
     * <p>
     * This method adds no padding or line wraps.
     * </p>
     *
     * @param byteArray Binary data
     * @return Encoded data as a String
     */
    public static String encode(byte[] byteArray) {
        return ENCODER.encodeToString(byteArray);
    }
}
