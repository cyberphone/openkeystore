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

/**
 * Collection of support functions for arrays.
 * <p>
 * To be deprecated in favor of {@link java.util.Arrays}.
 * </p>
 */
public class ArrayUtil {

    private ArrayUtil() {}  // No instantiation please

    /*
     * Find first difference between two byte arrays.
     * return First index i < length for which 
     * a[aOffset + i] != b[bOffset + i], 
     * or -1 if no differences are found.
     */
    public static int firstDiff(byte[] a, int aOffset, byte[] b, int bOffset, int length) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Cannot compare null arrays.");
        }
        if (aOffset + length > a.length ||
                bOffset + length > b.length) {
            throw new ArrayIndexOutOfBoundsException("Range to compare not contained in array.");
        }
        if (a == b && aOffset == bOffset) {
            return -1;
        }
        for (int i = 0; i < length; i++) {
            if (a[aOffset + i] != b[bOffset + i]) {
                System.out.println(i + ": " + Integer.toHexString(0xFF & a[aOffset + i]) + " " + Integer.toHexString(0xFF & b[bOffset + i]));
                return i;
            }
        }
        return -1;
    }

    /*
     * Find first difference between two byte arrays.
     */
    public static int firstDiff(byte[] a, byte[] b, int offset, int length) {
        return firstDiff(a, offset, b, offset, length);
    }

    /*
     * Find first difference between two byte arrays.
     */
    public static int firstDiff(byte[] a, byte[] b) {
        return firstDiff(a, b, 0, Math.min(a.length, b.length));
    }

    public static int indexOfMin(int[] a) {
        if (a.length == 0) {
            throw new IllegalArgumentException("Empty array.");
        } else {
            int r = 0;
            for (int i = 1; i < a.length; i++) {
                if (a[i] < a[r]) {
                    r = i;
                }
            }
            return r;
        }
    }

    /*
     * Returns the index of the (first) maximal element of an <code>int</code> array.
     * return The index of the (first) maximal element.
     * throws IllegalArgumentException If <code><i>a</i></code> is empty.
     */
    public static int indexOfMax(int[] a) {
        if (a.length == 0) {
            throw new IllegalArgumentException("Empty array.");
        } else {
            int r = 0;
            for (int i = 1; i < a.length; i++) {
                if (a[i] > a[r]) {
                    r = i;
                }
            }
            return r;
        }
    }

    /*
     * Returns the minimal element of an <code>int</code> array.
     * throws IllegalArgumentException If <code><i>a</i></code> is empty.
     */
    public static int min(int[] a) {
        return a[indexOfMin(a)];
    }

    /*
     * Returns the maximal element of an <code>int</code> array.
     * throws IllegalArgumentException If <code><i>a</i></code> is empty.
     */
    public static int max(int[] a) {
        return a[indexOfMax(a)];
    }

    /*
     * Convert byte array to hex string with formating options.
     * @param maxLength Max number of bytes to convert (-1 for full string).
     * @param separator Character to insert between converted bytes ('\0' for none).
     * @param uppercase Use uppercase letters (for hex symbols).
     * @return String
     */
    public static String toHexString(byte[] value, int startOffset,
                                     int maxLength,
                                     boolean uppercase, char separator) {
        if (maxLength == -1 || startOffset + maxLength > value.length) {
            maxLength = value.length - startOffset;
        }
        StringBuilder r = new StringBuilder(maxLength * (separator == -1 ? 2 : 3));
        for (int i = 0; i < maxLength; i++) {
            if (i > 0 && separator != 0) {
                r.append(separator);
            }
            String t = Integer.toHexString(value[i + startOffset] & 0xFF);
            if (t.length() == 1) {
                t = "0" + t;
            }
            if (uppercase) {
                t = t.toUpperCase();
            }
            r.append(t);
        }
        return r.toString();
    }

    /*
     * Convert byte array to hex string.
     * Calls the more configurable {@link #toHexString(byte[], int, int, boolean, char) 
     * toHexString} with uppercase set to true and space as separator character.
     */
    public static String toHexString(byte[] value, int startOffset,
                                     int maxLength) {
        return toHexString(value, startOffset, maxLength, true, ' ');
    }

    /*
     * Convert byte array to hex string.
     * Calls the more configurable {@link #toHexString(byte[], int, int, boolean, char) 
     * toHexString} with no offset, no max length, uppercase set to true and 
     * space as separator character.
     */
    public static String toHexString(byte[] value) {
        return toHexString(value, 0, -1, true, ' ');
    }

    /*
     * Convert int to hex string.
     * Calls {@link #toHexString(byte[], int, int, boolean, char) toHexString} with an array
     * containing the byte representation of the integer (little-endian).
     */
    public static String toHexString(int value, char byteSeparator) {
        return toHexString(new byte[]{(byte) ((value >> 24) & 0xFF),
                (byte) ((value >> 16) & 0xFF),
                (byte) ((value >> 8) & 0xFF),
                (byte) (value & 0xFF)}, 0, -1, true, byteSeparator);
    }

    /*
     * Copies a part or the whole of the supplied byte array to a new array of the indicated size.
     * If <i>newSize</i> is larger than <code>b.length</code> the remaining bytes of the 
     * result array will be set to zero.
     */
    public static byte[] copy(byte[] b, int newSize) {
        byte[] r = new byte[newSize];
        System.arraycopy(b, 0, r, 0, Math.min(b.length, r.length));
        return r;
    }

    /*
     * Makes a copy of the supplied byte array.
     */
    public static byte[] copy(byte[] b) {
        return copy(b, b.length);
    }

    /*
     * return the added byte array.
     */
    public static byte[] add(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /*
     * Makes a reversed copy of the supplied byte array.
     */
    public static byte[] reverse(byte[] b) {
        final int l = b.length;
        byte[] r = new byte[l];
        for (int i = 0; i < l; i++) {
            r[i] = b[l - i - 1];
        }
        return r;
    }
}
