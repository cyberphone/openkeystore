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

//#if ANDROID
// Source configured for Android.
//#else
// Source configured for JDK.
//#endif

/**
 * Encodes/decodes base64URL data.
 * See RFC 4648 Table 2.
 */
public class Base64URL {
//#if !ANDROID

    private static final java.util.Base64.Encoder ENCODER = 
            java.util.Base64.getUrlEncoder().withoutPadding();

    private static final java.util.Base64.Decoder DECODER = 
            java.util.Base64.getUrlDecoder();
//#endif

    private Base64URL() {}  // No instantiation please

    /**
     * Converts a base64url String to a byte array.
     * <p>
     * This method <b>does not</b> accept padding or line wraps.
     * </p>
     *
     * @param base64url Encoded data
     * @return Decoded data as a byte array
     */
    public static byte[] decode(String base64url) {
        if (base64url.contains("=")) {
            throw new IllegalArgumentException("Padding not allowed");
        }
//#if ANDROID
        return android.util.Base64.decode(base64url, android.util.Base64.URL_SAFE);
//#else
        return DECODER.decode(base64url);
//#endif
    }

    /**
     * Converts a base64url String to a byte array.
     * <p>
     * This method accepts <i>optional</i> padding.
     * </p>
     * <p>
     * Note that line wraps are <b>not</b> permitted.
     * </p>
     * 
     * @param base64url Encoded data
     * @return Decoded data as a byte array
     */
    public static byte[] decodePadded(String base64url) {
//#if ANDROID
        return android.util.Base64.decode(base64url, android.util.Base64.URL_SAFE);
//#else
        return DECODER.decode(base64url);
//#endif
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
//#if ANDROID
        return android.util.Base64.encodeToString(byteArray,
                                                  android.util.Base64.URL_SAFE |
                                                    android.util.Base64.NO_PADDING |
                                                    android.util.Base64.NO_WRAP);
//#else
        return ENCODER.encodeToString(byteArray);
//#endif
    }
}