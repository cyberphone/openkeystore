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

import org.webpki.util.DoubleCoreSerializer;

/**
 * Class for holding CBOR <code>floating&nbsp;point</code> objects.
 * <p>
 * Numbers are constrained to the IEEE 754 notation
 * using the length 16, 32, and 64 bit on "wire".  Which
 * length to use is governed by the size and precision 
 * required to (minimally) correctly represent a number.
 * </p>
 */
public class CBORFloat extends CBORObject {

    /**
     * Controls acceptance of exceptional floating point values.
     * <p>
     * By default, this implementation supports <code>NaN</code>, <code>Infinity</code>, 
     * and <code>-Infinity</code>. In case these variants are not applicable for the
     * application in question, they can be "outlawed" (causing an {@link CBORException} 
     * if encountered), by setting this <i>global</i> property to <code>true</code>.
     * Note: this setting affects both encoding and decoding.
     * </p>
     */
    public static boolean disableInvalidFloats = false;

    // Actual value.
    double value;
    
    // CBOR representation of value.
    int tag;
    long bitFormat;
    
    /**
     * Creates a CBOR <code>floating point</code>.
     * <p>
     * Note that this implementation does not provide a specific constructor
     * for Java <code>float</code> values.
     * Due to the CBOR normalization algorithm, numbers are still correctly encoded.
     * </p>
     * <p>
     * Also see {@link CBORObject#getDouble()} and {@link CBORObject#getFloat()}
     * </p>
     * 
     * @param value Java double
     */
    public CBORFloat(double value) {
        super(CBORTypes.FLOATING_POINT);
        this.value = value;

        // Initial assumption: the number is a plain vanilla 64-bit double.

        tag = MT_FLOAT64;
        bitFormat = Double.doubleToLongBits(value);

        // Check for possible edge cases.

        if ((bitFormat & ~FLOAT64_NEG_ZERO) == FLOAT64_POS_ZERO) {

            // Some zeroes are apparently more zero than others :)
            tag = MT_FLOAT16;
            bitFormat = (bitFormat == FLOAT64_POS_ZERO) ? FLOAT16_POS_ZERO : FLOAT16_NEG_ZERO;

        } else if ((bitFormat & FLOAT64_POS_INFINITY) == FLOAT64_POS_INFINITY) {

            // Special "number".
            if (disableInvalidFloats) {
                cborError("\"NaN\" and \"Infinity\" support is disabled");
            }
            tag = MT_FLOAT16;
            bitFormat = (bitFormat == FLOAT64_POS_INFINITY) ?
                FLOAT16_POS_INFINITY : (bitFormat == FLOAT64_NEG_INFINITY) ?
                    // Deterministic representation of NaN => Only "quiet" NaN is supported.
                    FLOAT16_NEG_INFINITY : FLOAT16_NOT_A_NUMBER;

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
                ((1l << FLOAT32_EXPONENT_SIZE) - 1)) -
                    (FLOAT32_EXPONENT_BIAS - FLOAT16_EXPONENT_BIAS);
            if (exponent <= -FLOAT16_SIGNIFICAND_SIZE || exponent > (FLOAT16_EXPONENT_BIAS << 1)) {
                // Too small or too big for float16, or running into float16 NaN/Infinity space.
                return;
            }

            long significand = bitFormat & ((1l << FLOAT32_SIGNIFICAND_SIZE) - 1);
            if ((significand & 
                (1l << (FLOAT32_SIGNIFICAND_SIZE - FLOAT16_SIGNIFICAND_SIZE)) -1) != 0) {
                // Losing significand bits is not an option.
                return;
            }
            significand >>= (FLOAT32_SIGNIFICAND_SIZE - FLOAT16_SIGNIFICAND_SIZE);

            // Check if we need to denormalize data.

            if (exponent <= 0) {
                // The implicit "1" becomes explicit using subnormal representation.
                significand += 1l << FLOAT16_SIGNIFICAND_SIZE;
                long significandCopy = significand;
                significand >>= (1 - exponent);
                if (significandCopy != (significand << (1 - exponent))) {
                    // Too off scale for denormalized float16.
                    return;
                }
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
     * Returns number in diagnostic notation.
     * <p>
     * Floating point numbers are always serialized using at least
     * one integer digit (may be <code>0</code>), a decimal point, and
     * one or more fractional digits. 
     * </p>
     * Possible exponents are written as <code>e&pm;</code><i>n</i>, where <i>n</i> != <code>0</code>.
     * 
     * @param value The double
     * @return The double in string format
     */
    public static String formatDouble(Double value) {
        // Catch things the serializer is not designed for.
        if (value == 0 || value.isInfinite() || value.isNaN()) {
            return value.toString();
        }
        return DoubleCoreSerializer.serialize(value, false);
    }

    /**
     * Returns the size of the optimized IEEE 754 type.
     * <p>
     * Note that you must cast a {@link CBORObject} to {@link CBORFloat}
     * in order to access {@link CBORFloat#size()}.
     * </p>
     * @return Size in bytes: 2, 4, or 8.
     */
    public int size() {
        return 2 << (tag - MT_FLOAT16);
    }

    @Override
    byte[] internalEncode() {
        return encodeTagAndValue(tag, size(), bitFormat);
    }
    
    @Override
    void internalToString(CborPrinter cborPrinter) {
         cborPrinter.append(formatDouble(value));
    }
}
