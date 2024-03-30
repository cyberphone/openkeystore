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

// Source configured for JDK.

/**
 * Encodes/decodes base64 data.
 */
public class Base64 {

    private static final java.util.Base64.Encoder ENCODER = 
            java.util.Base64.getEncoder().withoutPadding();

    private static final java.util.Base64.Encoder MIME_ENCODER = 
            java.util.Base64.getMimeEncoder(76, new byte[]{'\n'});

    private static final java.util.Base64.Decoder DECODER = 
            java.util.Base64.getDecoder();

    private Base64() {}  // No instantiation please

    /**
     * Decodes a base64 String to a byte array.
     * <p>
     * Note that line wraps are <i>ignored</i>.
     * </p>
     *
     * @param base64 Encoded data
     * @return Decoded data as a byte array
     */
    public static byte[] decode(String base64) {
        return DECODER.decode(base64.replace("\n", "").replace("\r", ""));
    }

    /**
     * Encodes a byte array to a base64 String.
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

    /**
     * Encodes a byte array to a base64 String.
     * <p>
     * This method wraps lines and adds padding.
     * </p>
     *
     * @param byteArray Binary data
     * @return Encoded data as a String
     */
    public static String mimeEncode(byte[] byteArray) {
        return MIME_ENCODER.encodeToString(byteArray);
    }
}
