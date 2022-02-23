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
package org.webpki.cbor;

import java.io.IOException;

/**
 * Class for holding CBOR floating point numbers.
 * <p>
 * Numbers are constrained to the IEEE 754 notation
 * using the length 16, 32, and 64 bit on "wire".  Which
 * length to use is governed by the size and precision 
 * required to (minimally) correctly represent a number.
 * API-wise numbers are only communicated as
 * 64-bit items (Java double).
 * </p>
 */
public class CBORFloatingPoint extends CBORObject {

    double value;
    
    /**
     * CBOR representation of value
     */
    int tag;
    long bitFormat;
    
    /**
     * Creates a CBOR <code>floating point</code>.
     * 
     * @param value
     */
    public CBORFloatingPoint(double value) {
        this.value = value;
        
        // Initial assumption: it is a plain vanilla 64-bit double.
        tag = MT_FLOAT64;
        bitFormat = Double.doubleToLongBits(value);

        // Check for possible edge cases.
        if ((bitFormat & ~FLOAT64_NEG_ZERO) == FLOAT64_POS_ZERO) {
            // Some zeroes are more zero than others.
            tag = MT_FLOAT16;
            bitFormat = (bitFormat == FLOAT64_POS_ZERO) ? FLOAT16_POS_ZERO : FLOAT16_NEG_ZERO;
        } else if ((bitFormat & FLOAT64_POS_INFINITY) == FLOAT64_POS_INFINITY) {
            // Special "number".
            tag = MT_FLOAT16;
            bitFormat = (bitFormat == FLOAT64_POS_INFINITY) ?
                FLOAT16_POS_INFINITY : (bitFormat == FLOAT64_NEG_INFINITY) ?
                    // Deterministic representation of NaN => No NaN "signaling".
                    FLOAT16_NEG_INFINITY : FLOAT16_NOT_A_NUMBER;
        } else {
            // It is apparently a regular number. Does it fit in a 32-bit float?
            long exp32 = ((bitFormat >>> FLOAT64_FRACTION_SIZE) & 
                    ((1l << FLOAT64_EXPONENT_SIZE) - 1)) -
                        (FLOAT64_EXPONENT_BIAS - FLOAT32_EXPONENT_BIAS);
            long frac32 = (bitFormat >> (FLOAT64_FRACTION_SIZE - FLOAT32_FRACTION_SIZE)) & 
                    ((1l << FLOAT32_FRACTION_SIZE) - 1);

            // Too big for float32 or into the space reserved for NaN and Infinity.
            if (exp32 > (FLOAT32_EXPONENT_BIAS << 1)) {
                return;
            }

            // Losing fraction bits is not an option.
            if ((bitFormat & ((1l << FLOAT64_FRACTION_SIZE) - 1)) != 
                (frac32 << (FLOAT64_FRACTION_SIZE - FLOAT32_FRACTION_SIZE))) {
                return;
            }

            // Check if we need to denormalize data.
            if (exp32 <= 0) {
                // The implicit "1" becomes explicit using subnormal representation.
                frac32 += 1l << FLOAT32_FRACTION_SIZE;
                exp32--;
                // Always do at least one turn.
                do {
                    if ((frac32 & 1) != 0) {
                        // Too off scale for float32.
                        // This test also catches subnormal float64 numbers.
                        return;
                    }
                    frac32 >>= 1;
                } while (++exp32 < 0);
            }

            // New assumption: we settle on 32-bit float representation.
            tag = MT_FLOAT32;
            bitFormat = 
                // Put possible sign bit in position.
                ((bitFormat >>> (64 - 32)) & FLOAT32_NEG_ZERO) +
                // Exponent.  Put it in front of fraction.
                (exp32 << FLOAT32_FRACTION_SIZE) +
                // Fraction.
                frac32;
 
            // However, we must still check if the number could fit in a 16-bit float.
            long exp16 = exp32 - (FLOAT32_EXPONENT_BIAS - FLOAT16_EXPONENT_BIAS);
            long frac16 = frac32 >> (FLOAT32_FRACTION_SIZE - FLOAT16_FRACTION_SIZE);

            // Too big for float16 or into the space reserved for NaN and Infinity.
            if (exp16 > (FLOAT16_EXPONENT_BIAS << 1)) {
                return;
            }

            // Losing fraction bits is not an option.
            if ((bitFormat & ((1l << FLOAT32_FRACTION_SIZE) - 1)) != 
                (frac16 << (FLOAT32_FRACTION_SIZE - FLOAT16_FRACTION_SIZE))) {
                return;
            }

            // Check if we need to denormalize data.
            if (exp16 <= 0) {
                // The implicit "1" becomes explicit using subnormal representation.
                frac16 += 1l << FLOAT16_FRACTION_SIZE;
                exp16--;
                // Always do at least one turn.
                do {
                    if ((frac16 & 1) != 0) {
                        // Too off scale for float16.
                        // This test also catches subnormal float32 numbers.
                        return;
                    }
                    frac16 >>= 1;
                } while (++exp16 < 0);
            }

            // Seems like 16 bits indeed are sufficient!
            tag = MT_FLOAT16;
            bitFormat = 
                // Put possible sign bit in position.
                ((bitFormat >>> (32 - 16)) & FLOAT16_NEG_ZERO) +
                // Exponent.  Put it in front of fraction.
                (exp16 << FLOAT16_FRACTION_SIZE) +
                // Fraction.
                frac16;
        }
    }

    /**
     * A slightly nicer formatter than Java's original
     * 
     * @param value The double
     * @return The double in string format
     */
    public static String formatDouble(double value) {
        return Double.toString(value).replace('E', 'e').replaceAll("e(\\d)", "e+$1");
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.FLOATING_POINT;
    }
    
    @Override
    byte[] internalEncode() throws IOException {
        return encodeTagAndValue(tag, 2 << (tag - MT_FLOAT16), bitFormat);
    }
    
    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
         cborPrinter.append(formatDouble(value));
    }
}
