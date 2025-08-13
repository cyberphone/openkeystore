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

import org.webpki.util.HexaDecimal;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <i>non-finite</i> <code>float</code> objects.
 * <p>
 * See also {@link CBORFloat}.
 * </p>
 */
public class CBORNonFinite extends CBORObject {

    static final BigInteger MASK64 = new BigInteger("ffffffffffffffff", 16);

    // Original value.
    long original;

    // Encoding data
    long value;
    byte[] encoded;

    /**
     * Creates a CBOR <i>non-finite</i> <code>float</code> object.
     * <p>
     * See also {@link CBORObject#getFloat64()} and {@link CBORObject#getFloat32()}
     * </p>
     * <p>
     * 
     * @param value Java long holding a 16, 32, or 64-bit non-finite number.
     * @throws CBORException
     */
    @SuppressWarnings("this-escape")
    public CBORNonFinite(long value) {
        original = value;
        while (true) {
            this.value = value;
            encoded = BigInteger.valueOf(value).and(MASK64).toByteArray();
            if (this.encoded[0] == 0x00) {
                byte[] woZero = new byte[encoded.length - 1];
                System.arraycopy(encoded, 1, woZero, 0, woZero.length);
                encoded = woZero;
            }
            long pattern = switch (encoded.length) {
                case 2 -> 0x7c00L;
                case 4 -> 0x7f800000L;
                case 8 -> 0x7ff0000000000000L;
                default -> {
                    badValue();
                    yield 0;
                }
            };
            boolean signed = encoded[0] < 0;
            if ((value & pattern) != pattern) {
                badValue();
            }
            switch (encoded.length) {
                case 4:
                    if ((value & ((1L << 13) - 1L)) != 0) {
                        break;
                    }
                    value >>= 13;
                    value &= 0x7fffL;
                    if (signed) {
                        value |= 0x8000L;
                    }
                    continue;
                case 8:
                    if ((value & ((1L << 29) - 1L)) != 0) {
                        break;
                    }
                    value >>= 29;
                    value &= 0x7fffffffL;
                    if (signed) {
                        value |= 0x80000000L;
                    }
                    continue;
            }
            return;
        }
    }

    /**
     * Get length of the optimized IEEE 754 type.
     * <p>
     * Note that you must cast a {@link CBORObject} to {@link CBORNonFinite}
     * in order to access {@link CBORNonFinite#length()}.
     * </p>
     * @return Length in bytes: 2, 4, or 8.
     */
    public int length() {
        return encoded.length;
    }

    public boolean isBasic(boolean allFlag) {
        return encoded.length == 2 ?
            switch ((int)value) {
                case 0x7e00 -> true;
                case 0x7c00, 0xfc00 -> allFlag;
                default -> false;
            } : false;
    }

    void badValue () {
        cborError("Invalid non-finite argument: " + Long.toUnsignedString(original, 16));
    }

    long toNonFinite64(int significandLength) {
        long value64 = value;
        value64 &= (1L << significandLength) - 1L;
        value64 = 0x7ff0000000000000L | (value64 << (52 - significandLength));
        if (encoded[0] < 0) {
            value64 |= 0x8000000000000000L;
        }
        return value64;       
    }

    long _get() {
        return switch (encoded.length) {
            case 2 -> toNonFinite64(10);
            case 4 -> toNonFinite64(23);
            default -> value;
        };
    }

    @Override
    byte[] internalEncode() {
        return addByteArrays(new byte[]{(byte)(0xf9 + (encoded.length >> 2))}, encoded);
    }
    
    @Override
    void internalToString(CborPrinter cborPrinter) {
        if (isBasic(true)) {
            cborPrinter.append(isBasic(false) ? "NaN" : encoded[0] < 0 ? "-Infinity" : "Infinity");
        } else {
            cborPrinter.append("float'").append(HexaDecimal.encode(encoded)).append("'");
        }
    }
}
