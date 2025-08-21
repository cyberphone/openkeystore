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

import org.webpki.util.Float64Stringifier;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>float</code> objects.
 * <p>
 * Numbers are in the <code>IEEE-754</code> format
 * using the length <code>16</code>, <code>32</code>, and <code>64</code> bit on the "wire".  Which
 * length to use is governed by the size and precision 
 * required to (minimally) correctly represent a number.
 * </p>
 */
public class CBORFloat extends CBORObject {

    // Actual value.
    double value;
    
    // CBOR representation of value.
    int tag;
    long bitFormat;

    /**
     * Creates a CBOR <code>float</code> object.
     * <p>
     * This constructor only implements support for finite ("regular") floating point
     * numbers.  That is, a {@link Double#NaN} argument causes a {@link CBORException}
     * to be thrown.
     * </p>
     * <p>
     * {@link CBORObject#getFloat64()} is the <i>decoder</i> counterpart.
     * </p>
     * <p>
     * For <code>NaN</code> and <code>Infinity</code> support see
     * {@link CBORFloat#createExtendedFloat(double)}.
     * </p>
     * 
     * @param value Floating-point value
     */
    public CBORFloat(double value) {
        this.value = value;

        // Initial assumption: the number is a plain vanilla 64-bit double.

        tag = MT_FLOAT64;
        bitFormat = Double.doubleToRawLongBits(value);

        // Check for forbidden numbers.

        if ((bitFormat & FLOAT64_POS_INFINITY) == FLOAT64_POS_INFINITY) {

            // Non-finite numbers: Infinity, -Infinity, and NaN.
            cborError(STDERR_NON_FINITE_NOT_PERMITTED);

        }

        if ((bitFormat & ~FLOAT64_NEG_ZERO) == FLOAT64_POS_ZERO) {

            // Some zeroes are apparently more zero than others :)
            tag = MT_FLOAT16;
            bitFormat = (bitFormat == FLOAT64_POS_ZERO) ? FLOAT16_POS_ZERO : FLOAT16_NEG_ZERO;

        } else {

            // It must be a "regular" number. Does it fit in a 32-bit float?
 
            // The following code presumes that the underlying floating point system handles
            // overflow conditions and subnormal numbers that may be the result of a conversion.  
            if (value != (double)((float) value)) {
                // "Lost in translation".  Stick to float64.
                return;
            }

            // Yes, the number is compatible with 32-bit float representation.

            tag = MT_FLOAT32;
            bitFormat = Float.floatToIntBits((float)value) & MASK_LOWER_32;
            
            // However, we must still check if the number could fit in a 16-bit float.

            long exponent = ((bitFormat >>> FLOAT32_SIGNIFICAND_SIZE) & 
                ((1L << FLOAT32_EXPONENT_SIZE) - 1)) -
                    (FLOAT32_EXPONENT_BIAS - FLOAT16_EXPONENT_BIAS);
            if (exponent <= -FLOAT16_SIGNIFICAND_SIZE || exponent > (FLOAT16_EXPONENT_BIAS << 1)) {
                // Too small or too big for float16, or running into float16 NaN/Infinity space.
                return;
            }

            long significand = bitFormat & ((1L << FLOAT32_SIGNIFICAND_SIZE) - 1);
            if ((significand & 
                (1L << (FLOAT32_SIGNIFICAND_SIZE - FLOAT16_SIGNIFICAND_SIZE)) -1) != 0) {
                // Losing significand bits is not an option.
                return;
            }
            significand >>= (FLOAT32_SIGNIFICAND_SIZE - FLOAT16_SIGNIFICAND_SIZE);

            // Check if we need to denormalize data.

            // Note: exponent == (1 - FLOAT16_SIGNIFICAND_SIZE) only denormalizes
            // properly if significand is zero => smallest denormalized number.

            if (exponent <= 0) {
                if ((significand & ((1L << (1 - exponent)) - 1)) != 0) {
                    // Losing significand bits is not an option.
                    return;
                }
                // The implicit "1" becomes explicit using subnormal representation.
                significand += (1L << FLOAT16_SIGNIFICAND_SIZE);
                // Put significand in position.
                significand >>= (1 - exponent);
                // Denormalized exponents are always zero.
                exponent = 0;
            }

            // Seems like 16 bits indeed are sufficient!

            tag = MT_FLOAT16;
            bitFormat = 
                // Put sign bit in position.
                ((bitFormat >>> (32 - 16)) & FLOAT16_NEG_ZERO) +
                // Exponent.  Put it in front of significand.
                (exponent << FLOAT16_SIGNIFICAND_SIZE) +
                // Significand.
                significand;
        }
    }

     /**
     * Creates an "extended" CBOR <code>float</code> object.
     * <p>
     * Unlike {@link CBORFloat#CBORFloat(double)}, this method also supports the "simple" <code>NaN</code> 
     * and the two <code>Infinity</code> variants.
     * </p>
     * <p>
     * {@link CBORObject#getExtendedFloat64()} is the <i>decoder</i> counterpart.
     * </p>
     * <p>
     * Note that return type is either {@link CBORFloat} or {@link CBORNonFinite}, depending
     * on if the argument is a "regular" floating-point value of one of the non-finite variants.
     * </p>
     * @param value Floating-point value
     * @return {@link CBORObject}
     * @throws CBORException
     * @see CBORNonFinite#CBORNonFinite(long)
     */
    public static CBORObject createExtendedFloat(double value) {
        if (Double.isFinite(value)) {
            return new CBORFloat(value);
        }
        if (Double.isNaN(value)) value = Double.NaN;  // Sorry, only "simple" NaNs apply.
        return new CBORNonFinite(Double.doubleToRawLongBits(value));
    }

    /**
     * Get length of the serialized <code>IEEE-754</code> object.
     * <p>
     * Note that you must cast a {@link CBORObject} to {@link CBORFloat}
     * in order to access {@link CBORFloat#length()}.
     * </p>
     * @return Length in bytes: 2, 4, or 8.
     */
    public int length() {
        return 2 << (tag - MT_FLOAT16);
    }

    @Override
    byte[] internalEncode() {
        return encodeTagAndValue(tag, length(), bitFormat);
    }
    
    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append((value == 0 || !Double.isFinite(value)) ?
            String.valueOf(value) : Float64Stringifier.encode(value, false));
    }

    static final String STDERR_NON_FINITE_NOT_PERMITTED = 
            "Not permitted, see \"CBORNonFinite\" for details";

}
