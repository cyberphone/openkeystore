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

    void createDetermnisticEncoding(long value) {
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
     * Creates a CBOR <i>non-finite</i> <code>float</code> object.
     * <p>
     * The constructor takes a <code>16</code>, <code>32</code>, or <code>64</code>-bit
     * non-finite number in <code>IEEE-754</code> encoding.
     * </p>
     * <p>
     * See also {@link CBORFloat#CBORFloat(double)} and {@link CBORFloat#createExtended(double)}.
     * </p>
     * 
     * @param value <code>long</code> holding the number
     * @throws CBORException If the argument is not within the non-finite number space
     */
    @SuppressWarnings("this-escape")
    public CBORNonFinite(long value) {
        createDetermnisticEncoding(value);
    }

    /**
     * Creates a payload object.
     * <div style='margin-top:0.8em'>
     * Traditionally, the non-finite number space is used for propagating
     * math-related problems such as division by zero.
     * </div>
     * <div style='margin-top:0.5em'>
     * However, in some cases there may be a desire providing more application specific data,
     * like debug information related to faulty sensors.
     * The {@link #createPayloadObject(long)} and {@link #getPayloadData()}
     * methods were designed for this particular purpose.
     * To obviate the need defining another CBOR type, these methods
     * are "piggybacking" on the existing non-finite number space.
     * The following table represents these methods from a <i>developer</i> perspective:
     * </div>
     * <div class='webpkifloat'><table class='webpkitable' style='margin-left:2em'>
     * <tr><th>Payload</th></tr>
     * <tr><td><code>d51-d0</code> in <i>big-endian</i> order</td></tr>
     * </table></div>
     * <div style='margin-top:0.5em'>
     * The payload bits are conceptually put into an <code>IEEE-754</code>
     * <code>64</code>-bit object having the following layout:
     * </div>
     * <div class='webpkifloat'><table class='webpkitable' style='margin-left:2em'>
     * <tr><th>Sign</th><th>Exponent</th><th>Significand</th></tr>
     * <tr style='text-align:center'><td>0</td><td>11111111111</td><td style='white-space:nowrap'><code>d0-d51</code> in <i>little-endian</i> order</td></tr>
     * </table></div>
     * <div>
     * For setting the sign bit, see {@link #setSign(boolean)}.
     * </div>
     * <div style='margin-top:0.7em'>
     * The reason for <i>reversing</i> the payload bits is to ensure that a specific bit will remain
     * in a fix position (maintain the same value), independent of the size of the
     * <code>IEEE-754</code> variant used for encoding.
     * </div>
     * <div style='margin-top:0.7em'>
     * Note that the encoder will (due to CBOR deterministic encoding rules), select
     * the shortest serialization required to properly represent the payload.
     * The following table shows a few examples:
     * </div>
     * <div class='webpkifloat'><table class='webpkitable' style='margin-left:2em'>
     * <tr><th>Payload (hex)</th><th>CBOR Encoding</th><th>Diagnostic Notation</th></tr>
     * <tr><td style='text-align:right'><code>0</code></td><td style='text-align:right'><code>f97c00</code></td><td><code>Infinity</code></td></tr>
     * <tr><td style='text-align:right'><code>1</code></td><td style='text-align:right'><code>f97e00</code></td><td><code>NaN</code></td></tr>
     * <tr><td style='text-align:right'><code>2</code></td><td style='text-align:right'><code>f97d00</code></td><td><code>float'7d00'</code></td></tr>
     * <tr><td style='text-align:right'><code>3ff</code></td><td style='text-align:right'><code>f97fff</code></td><td><code>float'7fff'</code></td></tr>
     * <tr><td style='text-align:right'><code>400</code></td><td style='text-align:right'><code>fa7f801000</code></td><td><code>float'7f801000'</code></td></tr>
     * <tr><td style='text-align:right'><code>7fffff</code></td><td style='text-align:right'><code>fa7fffffff</code></td><td><code>float'7fffffff'</code></td></tr>
     * <tr><td style='text-align:right'><code>800000</code></td><td style='text-align:right'><code>fb7ff0000010000000</code></td><td><code>float'7ff0000010000000'</code></td></tr>
     * <tr><td style='text-align:right'><code>fffffffffffff</code></td><td style='text-align:right'><code>fb7fffffffffffffff</code></td><td><code>float'7fffffffffffffff'</code></td></tr>
     * </table></div>
     * <div style='margin-top:0.7em'>
     * {@link CBORNonFinite#CBORNonFinite(long)} represents another way creating a non-finite <code>float</code>.
     * </div>
     * @param payload Payload
     * @return {@link CBORNonFinite}.  Also see <a href='../../webpki/cbor/package-summary.html#supported-objects'>CBOR wrapper objects</a>.
     * @see CBORFloat#createExtended(double)
     */
    public static CBORNonFinite createPayloadObject(long payload) {
        if ((payload & PAYLOAD_MASK) != payload) {
            cborError(STDERR_PAYLOAD_RANGE);
        }
        return new CBORNonFinite(
            FLOAT64_POS_INFINITY + CBORUtil.reverseBits(payload, FLOAT64_SIGNIFICAND_SIZE));
    }

    /**
     * Get payload data.
     * <p>
     * This method is the "consumer" counterpart to {@link #createPayloadObject(long)}.
     * </p>
     * @return Payload
     */
    public long getPayloadData() {
        return CBORUtil.reverseBits(getNonFinite64() & PAYLOAD_MASK, FLOAT64_SIGNIFICAND_SIZE);
    }

    /**
     * Set the sign bit of the non-finite <code>float</code>.
     * @param on Sign bit
     * @return {@link CBORNonFinite}
     * @see #getSign()
     */
    public CBORNonFinite setSign(boolean on) {
        long mask = 1L << ((encoded.length * 8) - 1L);
        createDetermnisticEncoding((value & (mask - 1L)) | (on ? mask : 0));
        return this;
    }

    /**
     * Get the sign bit of the non-finite <code>float</code>.
     * @return Sign bit expressed as a <code>boolean</code>
     * @see #setSign(boolean)
     */
    public boolean getSign() {
        return encoded[0] < 0;
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
     * <code>Infinity</code>, or <code>-Infinity</code>, else it returns <code>false</code>.
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
        if (getSign()) {
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
     * @return <code>IEEE-754</code> non-finite number coded as a <code>long</code>
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
     * @return <code>IEEE-754</code> non-finite number coded as a <code>long</code>
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
        return CBORUtil.concatByteArrays(new byte[]{(byte)(MT_FLOAT16 + (encoded.length >> 2))},
                                         encoded);
    }
    
    @Override
    void internalToString(CborPrinter cborPrinter) {
        if (isSimple()) {
            cborPrinter.append(isNaN() ? "NaN" : getSign() ? "-Infinity" : "Infinity");
        } else {
            cborPrinter.append("float'").append(HexaDecimal.encode(encoded)).append('\'');
        }
    }

    static final String STDERR_INVALID_NON_FINITE_ARGUMENT = 
            "Invalid non-finite argument: ";

    static final String STDERR_PAYLOAD_RANGE = 
            "Payloads are limited to bit d0-d51";

}
