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

import org.webpki.util.HexaDecimal;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <i>non-finite</i> <code>float</code> objects.
 * <p>
 * See also {@link CBORFloat}.
 * </p>
 */
public class CBORNonFinite extends CBORObject {

    // Original value.
    long original;

    // Encoding data
    long value;
    byte[] encoded;

    static final long DIFF_32_16 = FLOAT32_SIGNIFICAND_SIZE - FLOAT16_SIGNIFICAND_SIZE;
    static final long DIFF_64_32 = FLOAT64_SIGNIFICAND_SIZE - FLOAT32_SIGNIFICAND_SIZE;

    static final long PAYLOAD_MASK = ((1L << FLOAT64_SIGNIFICAND_SIZE) - 1L);

    /**
     * Creates a CBOR <i>non-finite</i> <code>float</code> object.
     * <p>
     * See also {@link CBORObject#getFloat64()} and {@link CBORObject#getFloat32()}
     * </p>
     * 
     * @param value Java long holding a 16, 32, or 64-bit non-finite number.
     * @throws CBORException
     */
    @SuppressWarnings("this-escape")
    public CBORNonFinite(long value) {
        original = value;
        while (true) {
            this.value = value;
            encoded = CBORUtil.unsignedLongToByteArray(value);
            long pattern = switch (encoded.length) {
                case 2 -> FLOAT16_POS_INFINITY;
                case 4 -> FLOAT32_POS_INFINITY;
                case 8 -> FLOAT64_POS_INFINITY;
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
                    if ((value & ((1L << DIFF_32_16) - 1L)) != 0) {
                        break;
                    }
                    value >>= DIFF_32_16;
                    value &= (FLOAT16_NEG_ZERO - 1L);
                    if (signed) {
                        value |= FLOAT16_NEG_ZERO;
                    }
                    continue;
                case 8:
                    if ((value & ((1L << DIFF_64_32) - 1L)) != 0) {
                        break;
                    }
                    value >>= DIFF_64_32;
                    value &= (FLOAT32_NEG_ZERO - 1L);
                    if (signed) {
                        value |= FLOAT32_NEG_ZERO;
                    }
                    continue;
            }
            return;
        }
    }

    static long reversePayloadBits(long payloadBits) {
        long reversed = 0;
        int bitCount = 0;
        while (payloadBits > 0) {
            bitCount++;
            reversed <<= 1;
            if ((payloadBits & 1) == 1)
                reversed |= 1;
            payloadBits >>= 1;
        }
        return reversed << (FLOAT64_SIGNIFICAND_SIZE - bitCount);
    }

    /**
     * Create a <code>NaN</code> with a payload.
     * <div style='margin-top:1em'>
     * The following table represents this method from a <i>developer</i> perspective:
     * </div>
     * <div>
     * <table class='webpkitable'>
     * <tr><th>Payload Bits</th></tr>
     * <tr><td><code>b52-b1</code> in <i>big-endian</i> format</td></tr>
     * </table>
     * </div>
     * <div>
     * Note that a payload with only zeros, cause a {@link CBORException} to be thrown.
     * </div>
     * <div style='margin-top:1em'>
     * Although provided here for <i>reference purposes</i> only, the payloads bits are
     * subsequently stuffed into an <code>IEEE-754</code> 64-bit object according to the following:
     * </div>
     * <div>
     * <table class='webpkitable'>
     * <tr><th>Sign &amp; Exponent</th><th>Significand</th></tr>
     * <tr><td style='text-align:center'>011111111111</th><td><code>b1-b52</code> in <i>little-endian</i> format</td></tr>
     * </table>
     * </div>
     * <div>
     * Note that the encoder will subsequently select the shortest serialization
     * required to properly represent the provided set of bits.
     * As an example, an argument of <code>6</code> (<code>b2</code> and <code>b3</code> bits are set),
     * would yield a CBOR item encoded as
     * <code>f97d80</code>, here shown in hexadecimal notation.
     * </div>
     * @param payloadBits Holds a set of application specific bits
     * @return {@link CBORNonFinite}.  Also see <a href='../../webpki/cbor/package-summary.html#supported-objects'>CBOR wrapper objects</a>.
     * @see CBORObject#getCombinedFloat64()
     * @see CBORFloat#createCombinedFloat(double)
     */
    public static CBORNonFinite createNanWithPayload(long payloadBits) {
        if (payloadBits == 0) {
            cborError("Payload must not be zero");
        }
        if ((payloadBits & PAYLOAD_MASK) != payloadBits) {
            cborError("Payload bits are limited to b0-b51");
        }
        return new CBORNonFinite(FLOAT64_POS_INFINITY + reversePayloadBits(payloadBits));
    }

    /**
     * Documention: to be writtem...
     */
    public long getNaNPayloadBits() {
        if (!isNaN()) {
            cborError("Not a NaN: " + this.toString());
        }
        return reversePayloadBits(getNonFinite64() & PAYLOAD_MASK);  // etNonFinite64() => Regular API
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

    /**
     * Documention: to be writtem...
     */
    public boolean isBasic(boolean allFlag) {
        return encoded.length == 2 ?
            switch ((int)value) {
                case (int)FLOAT16_NOT_A_NUMBER -> true;
                case (int)FLOAT16_POS_INFINITY, (int)FLOAT16_NEG_INFINITY -> allFlag;
                default -> false;
            } : false;
    }

    /**
     * Documention: to be writtem...
     */
    public boolean isNaN() {
        return (switch (encoded.length) {
            case 2 -> (1L << FLOAT16_SIGNIFICAND_SIZE) - 1L;
            case 4 -> (1L << FLOAT32_SIGNIFICAND_SIZE) - 1L;
            default -> (1L << FLOAT64_SIGNIFICAND_SIZE) - 1L;
        } & value) != 0;
    }

    void badValue () {
        cborError("Invalid non-finite argument: " + Long.toUnsignedString(original, 16));
    }

    long toNonFinite64(int significandLength) {
        long value64 = value;
        value64 &= (1L << significandLength) - 1L;
        value64 = FLOAT64_POS_INFINITY | (value64 << (52 - significandLength));
        if (encoded[0] < 0) {
            value64 |= FLOAT64_NEG_ZERO;
        }
        return value64;       
    }

    /**
     * Documention: to be writtem...
     */
    public long getNonFinite() {
        return value;
    }

    /**
     * Documention: to be writtem...
     */
    public long getNonFinite64() {
        return switch (encoded.length) {
            case 2 -> toNonFinite64(FLOAT16_SIGNIFICAND_SIZE);
            case 4 -> toNonFinite64(FLOAT32_SIGNIFICAND_SIZE);
            default -> value;
        };
    }

    @Override
    byte[] internalEncode() {
        return CBORUtil.concatByteArrays(new byte[]{(byte)(MT_FLOAT16 + (encoded.length >> 2))}, encoded);
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
