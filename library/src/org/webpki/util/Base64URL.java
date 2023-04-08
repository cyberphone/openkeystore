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
     * Converts a base64url String to a byte array.
     * <p>
     * This method <b>does not</b> accept padding.
     * </p>
     * <p>
     * Note that line wraps are <b>not</p> permitted.
     * </p>
     *
     * @param base64url Encoded data
     * @return Decoded data as a byte array
     */
    public static byte[] decode(String base64url) {
        if (base64url.contains("=")) {
            throw new IllegalArgumentException("Padding not allowed");
        }
        return DECODER.decode(base64url);
    }

    /**
     * Converts a base64url String to a byte array.
     * <p>
     * This method accepts <i>optional</i> padding.
     * </p>
     * <p>
     * Note that line wraps are <b>not</p> permitted.
     * </p>
     * 
     * @param base64url Encoded data
     * @return Decoded data as a byte array
     */
    public static byte[] decodePadded(String base64url) {
        return DECODER.decode(base64url);
    }

    /**
     * Converts a byte array to a base64url String.
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
