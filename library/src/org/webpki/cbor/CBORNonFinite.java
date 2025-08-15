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

    /**
     * Create a <code>NaN</code> with a payload.
     * <div style='margin-top:1em'>
     * The following table represents this method from a <i>developer</i> perspective:
     * </div>
     * <div>
     * <table class='webpkitable'>
     * <tr><th>Payload</th></tr>
     * <tr><td><code>d51-d0</code> in <i>big-endian</i> order</td></tr>
     * </table>
     * </div>
     * <div>
     * Note that a payload with only zeros, will force the encoder to set bit <code>d0</code>.
     * </div>
     * <div style='margin-top:1em'>
     * Although provided here for <i>reference purposes</i> only, the payloads bits are
     * subsequently stuffed into an <code>IEEE-754</code> 64-bit object according to the following:
     * </div>
     * <div>
     * <table class='webpkitable'>
     * <tr><th>Sign &amp; Exponent</th><th>Significand</th></tr>
     * <tr><td style='text-align:center'>011111111111</th><td><code>d0-d51</code> in <i>little-endian</i> order</td></tr>
     * </table>
     * </div>
     * <div>
     * Note that the encoder will subsequently select the shortest serialization
     * required to properly represent the provided set of bits.
     * As an example, an argument of <code>6</code> (<code>d1</code> and <code>d2</code> bits are set),
     * would yield a CBOR item encoded as <code>f97d80</code>, here shown in hexadecimal notation.
     * </div>
     * @param payload Holds a set of application specific bits
     * @return {@link CBORNonFinite}.  Also see <a href='../../webpki/cbor/package-summary.html#supported-objects'>CBOR wrapper objects</a>.
     * @see CBORFloat#createExpandedFloat(double)
     */
    public static CBORNonFinite createNaNPayload(long payload) {
        if (payload == 0) {
            payload = 1;  // "quiet" NaN
        }
        if ((payload & PAYLOAD_MASK) != payload) {
            cborError(STDERR_PAYLOAD_RANGE);
        }
        return new CBORNonFinite(
            FLOAT64_POS_INFINITY + CBORUtil.reverseBits(payload, FLOAT64_SIGNIFICAND_SIZE));
    }

    /**
     * Get <code>NaN</code> payload bits.
     * <p>
     * This method is the "consumer" counterpart to {@link #createNaNPayload(long)}.
     * Note that a "quiet" <code>NaN</code> (<code>7e00</code>) returns zero.
     * </p>
     * <p>
     * If the sign bit is also required, the {@link #getNonFinite64()}
     * method must be used.
     * </p>
     * @return <code>long</code>
     */
    public long getNaNPayload() {
        if (!isNaN()) {
            cborError(STDERR_NOT_A_NAN + this.toString());
        }
        // getNonFinite64() => Regular API
        long payload = CBORUtil.reverseBits(
            getNonFinite64() & PAYLOAD_MASK, FLOAT64_SIGNIFICAND_SIZE);
        return payload == 1 ? 0 : payload;  
    }

    /**
     * Get length of CBOR non-finite object.
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
     * Check if CBOR non-finite object is simple.
     * <p>
     * This method returns <code>true</code> if the non-finite object is a "quiet" <code>NaN</code>,
     * <code>Infinity</code>, or <code>-Infinity</code>,
     * else it returns <code>false</code>.
     * </p>
     * @return <code>boolean</code>. 
     */
    public boolean isSimple() {
        return encoded.length == 2 ?
            switch ((int)value) {
                case (int)FLOAT16_NOT_A_NUMBER,
                     (int)FLOAT16_POS_INFINITY, 
                     (int)FLOAT16_NEG_INFINITY -> true;
                default -> false;
            } : false;
    }

    /**
     * Check if CBOR non-finite object is a <code>NaN</code>.
     * <p>
     * This method returns <code>true</code> for <i>all conformant</i> <code>NaN</code> variants,
     * else it returns <code>false</code>.
     * </p>
     * @return <code>boolean</code>. 
     */
    public boolean isNaN() {
        return (switch (encoded.length) {
            case 2 -> (1L << FLOAT16_SIGNIFICAND_SIZE) - 1L;
            case 4 -> (1L << FLOAT32_SIGNIFICAND_SIZE) - 1L;
            default -> (1L << FLOAT64_SIGNIFICAND_SIZE) - 1L;
        } & value) != 0;
    }

    void badValue () {
        cborError(STDERR_INVALID_NON_FINITE_ARGUMENT + Long.toUnsignedString(original, 16));
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
     * Get <i>actual</i> CBOR non-finite <code>float</code> object.
     * <p>
     * This method returns the value of a CBOR non-finite
     * object.  The value is provided in the most compact form
     * based on CBOR serialization rules.
     * </p>
     * @return <code>long</code>
     */
    public long getNonFinite() {
        scan();
        return value;
    }

    /**
     * Get <i>expanded</i> CBOR non-finite <code>float</code> object.
     * <p>
     * This method returns the value of a CBOR non-finite
     * object after it has been expanded to 64 bits.
     * That is, a received <code>7c01</code> will be returned as <code>7ff0040000000000</code>.
     * </p>
     * @return <code>long</code>
     */
    public long getNonFinite64() {
        scan();
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
        if (isSimple()) {
            cborPrinter.append(isNaN() ? "NaN" : encoded[0] < 0 ? "-Infinity" : "Infinity");
        } else {
            cborPrinter.append("float'").append(HexaDecimal.encode(encoded)).append("'");
        }
    }

    static final String STDERR_INVALID_NON_FINITE_ARGUMENT = 
            "Invalid non-finite argument: ";

    static final String STDERR_NOT_A_NAN = 
            "Not a NaN: ";

    static final String STDERR_PAYLOAD_RANGE = 
            "Payloads are limited to bit d0-d51";
}
