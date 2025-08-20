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
 * Class for holding CBOR <i>non-finite</i> floating-point objects.
 * <p>
 * Due to the fact that platform support for non-finite floating-point objects
 * beyond the three simple forms, "quiet" <code>NaN</code>, <code>Infinity</code>,
 * and <code>-Infinity</code> is limited, this implementation <i>separates</i>
 * non-finite floating-point objects from "genuine" floating-point numbers.
 * The latter are dealt with by the {@link CBORFloat} class.
 * </p>
 * <p>
 * Since non-finite data can be "anything" that makes sence for consuming
 * applications, <code>long</code> is used as value container.
 * </p>
 * <p>
 * For a detailed description and user guide, turn to:
 * <a href='../../webpki/cbor/doc-files/non-finite-numbers.html'>Non-Finite Numbers</a>.
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
     * Creates a <i>non-finite</i> floating-point number.
     * <p>
     * The constructor takes a <code>16</code>, <code>32</code>, or <code>64</code>-bit
     * non-finite number in <code>IEEE-754</code> encoding.
     * </p>
     * <p>
     * See also {@link CBORFloat#CBORFloat(double)} and {@link CBORFloat#createExtendedFloat(double)}.
     * </p>
     * 
     * @param value Non-finite number expressed as a <code>long</code>
     * @throws CBORException If the argument is not within the non-finite number space
     */
    @SuppressWarnings("this-escape")
    public CBORNonFinite(long value) {
        createDetermnisticEncoding(value);
    }

    /**
     * Creates a payload object.
     * <div style='margin-top:0.7em'>
     * For details turn to
     * <a href='../../webpki/cbor/doc-files/non-finite-numbers.html#payload-option'>Payload Option</a>.
     * </div>
     * @param payloadData Payload data
     * @return {@link CBORNonFinite}
     * @see CBORFloat#createExtendedFloat(double)
     */
    public static CBORNonFinite createPayloadObject(long payloadData) {
        if ((payloadData & PAYLOAD_MASK) != payloadData) {
            cborError(STDERR_PAYLOAD_RANGE);
        }
        return new CBORNonFinite(
            FLOAT64_POS_INFINITY + CBORUtil.reverseBits(payloadData, FLOAT64_SIGNIFICAND_SIZE));
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
     * Set sign bit of non-finite object.
     * @param sign Sign bit expressed as a <code>boolean</code>. <code>true</code> = 1, <code>false</code> = 0.
     * @return {@link CBORNonFinite}
     * @see #getSign()
     */
    public CBORNonFinite setSign(boolean sign) {
        long mask = 1L << ((encoded.length * 8) - 1L);
        createDetermnisticEncoding((value & (mask - 1L)) | (sign ? mask : 0));
        return this;
    }

    /**
     * Get sign bit of non-finite object.
     * @return Sign bit expressed as a <code>boolean</code>. <code>true</code> = 1, <code>false</code> = 0.
     * @see #setSign(boolean)
     */
    public boolean getSign() {
        return encoded[0] < 0;
    }

    /**
     * Get length of non-finite object.
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
     * Check if non-finite object is simple.
     * <p>
     * This method returns <code>true</code> if the non-finite object is a "quiet" <code>NaN</code>,
     * <code>Infinity</code>, or <code>-Infinity</code>, else <code>false</code> is returned.
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
     * Check if non-finite object is a <code>NaN</code>.
     * <p>
     * This method returns <code>true</code> for <i>all conformant</i> <code>NaN</code> variants,
     * else <code>false</code> is returned..
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
        long f64 = value;
        f64 &= (1L << significandLength) - 1L;
        f64 = FLOAT64_POS_INFINITY | (f64 << (FLOAT64_SIGNIFICAND_SIZE - significandLength));
        if (getSign()) {
            f64 |= FLOAT64_NEG_ZERO;
        }
        return f64;       
    }

    /**
     * Get <i>actual</i> non-finite object (value).
     * <p>
     * This method returns the value of a non-finite
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
     * Get <i>expanded</i> non-finite object (value).
     * <p>
     * This method returns the value of a non-finite
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
