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
 * Encodes/decodes hexadecimal data.
 */
public class HexaDecimal {

    private HexaDecimal() {}

    private StringBuilder res = new StringBuilder(1000);

    private void put(char c) {
        res.append(c);
    }

    private void hex(int i) {
        if (i < 10) {
            put((char) (i + '0'));
        } else {
            put((char) (i + 'a' - 10));
        }
    }

    private void twohex(int i) {
        i &= 0xFF;
        hex(i / 16);
        hex(i % 16);
    }

    private void addrhex(int i) {
        if (i > 65535) {
            twohex(i / 65536);
            i %= 65536;
        }
        twohex(i / 256);
        twohex(i % 256);
    }

    private String toHexDebugData(byte[] indata, int bytesPerLine) {
        int index = 0;
        int i = 0;
        if (indata.length == 0) {
            return "No data";
        }
        boolean onlyData = false;
        if (bytesPerLine < 0) {
            bytesPerLine = -bytesPerLine;
            onlyData = true;
        }
        while (index < indata.length) {
            if (index > 0) {
                put('\n');
            }
            addrhex(index);
            put(':');
            int q = indata.length - index;
            if (q > bytesPerLine) {
                q = bytesPerLine;
            }
            for (i = 0; i < q; i++) {
                put(' ');
                twohex(indata[index + i]);
            }
            if (onlyData) {
                index += q;
                continue;
            }
            while (i++ <= bytesPerLine) {
                put(' ');
                put(' ');
                put(' ');
            }
            put('\'');
            for (i = 0; i < q; i++) {
                int c = (int) indata[index++];
                if (c < 32 || c >= 127) {
                    put('.');
                } else {
                    put((char) c);
                }
            }
            put('\'');
            while (i++ < bytesPerLine) {
                put(' ');
            }
        }
        return res.toString();
    }

    private String toHexString(byte[] indata) {
        int i = 0;
        while (i < indata.length) {
            twohex(indata[i++]);
        }
        return res.toString();
    }

    /**
     * Formats byte array data into readable lines.
     * <p>
     * After each line (<code>nn:&nbsp;hh&nbsp;hh...</code>) the ASCII counterpart is listed as well.
     * </p>
     * @param byteArray The data to be listed
     * @param bytesPerLine Bytes per line
     * @return Human-readable String
     */
    public static String getHexDebugData(byte[] byteArray, int bytesPerLine) {
        return new HexaDecimal().toHexDebugData(byteArray, bytesPerLine);
    }

    /**
     * Encodes byte array data.
     *
     * @param byteArray Data to be encoded
     * @return String with zero or more hexadecimal pairs (<code>hh</code>)
     */
    public static String encode(byte[] byteArray) {
        return new HexaDecimal().toHexString(byteArray);
    }

    static int toHex(char c) {
        if (c >= '0') {
            if (c <= '9') return c - '0';
            if (c >= 'a') {
                if (c <= 'f') return c - ('a' - 10);
            }
            if (c >= 'A') {
                if (c <= 'F') return c - ('A' - 10);
            }
        }
        throw new IllegalArgumentException("Bad hexchar: " + c);
    }

    /**
     * Decodes a hexadecimal String.
     * 
     * @param hexString String with zero or more hexadecimal pairs (<code>hh</code>)
     * @return byteArray
     */
    public static byte[] decode(String hexString) {
        int l = hexString.length();
        int bl;
        if (l % 2 != 0) throw new IllegalArgumentException("Bad hexstring: " + hexString);
        byte[] data = new byte[bl = l / 2];
        while (--bl >= 0) {
            data[bl] = (byte) (toHex(hexString.charAt(--l)) + (toHex(hexString.charAt(--l)) << 4));
        }
        return data;
    }
}
