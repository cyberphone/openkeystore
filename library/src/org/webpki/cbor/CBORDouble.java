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

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR floating point numbers.
 * Numbers are constrained to the IEEE 754 notation.
 */
public class CBORDouble extends CBORObject {

    double value;
    
    byte headerTag = MT_FLOAT16;
    long bitFormat;
    
    static final double MAX_HALF_FLOAT = 65504.0;
    
    /**
     * Create a CBOR <code>double</code> object.
     * 
     * @param value
     */
    public CBORDouble(double value) {
        this.value = value;
        bitFormat = Double.doubleToLongBits(value);
        double positiveValue = Math.abs(value);
        if (bitFormat == FLOAT64_POS_ZERO) {
            bitFormat = FLOAT16_POS_ZERO;
        } else if (bitFormat == FLOAT64_NEG_ZERO) {
            bitFormat = FLOAT16_NEG_ZERO;
        } else if (bitFormat == FLOAT64_NOT_A_NUMBER) {
            bitFormat = FLOAT16_NOT_A_NUMBER;
        } else if (bitFormat == FLOAT64_POS_INFINITY) {
            bitFormat = FLOAT16_POS_INFINITY;
        } else if (bitFormat == FLOAT64_NEG_INFINITY) {
            bitFormat = FLOAT16_NEG_INFINITY;
        } else if (positiveValue > Float.MAX_VALUE || 
                   positiveValue != (double)((float) positiveValue)) {
            // Too big or would lose precision unless we stick to 64 bits.
            headerTag = MT_FLOAT64; 
        } else { 
            // Assumption: we go for float32 unless proven wrong :)
            int float32BitFormat = Float.floatToIntBits((float)value);
            int exp16 = ((float32BitFormat >>> FLOAT32_FRACTION_SIZE) & 
                ((1 << FLOAT32_EXPONENT_SIZE) - 1)) + 
                    (FLOAT16_EXPONENT_BIAS - FLOAT32_EXPONENT_BIAS);
            // Complex test - would we lose precision using float16?
            int copyFloat = float32BitFormat;
            int q = exp16;
            while (q++ < 0) {
                if ((copyFloat & 1) != 0) {
                    positiveValue = Float.MAX_VALUE;
                    break;
                }
                copyFloat >>= 1;
            }
            // Our assumption was correct!
            if (positiveValue > MAX_HALF_FLOAT) {
                headerTag = MT_FLOAT32;
                bitFormat = float32BitFormat;
                return;
            }
            // Seems like float16 will work!
/* System.out.println("Exp16l=" + Long.toString(((bitFormat >>> FLOAT64_FRACTION_SIZE) & 
   ((1l << FLOAT64_EXPONENT_SIZE) - 1)),16)); */
           int frac16 = (float32BitFormat >>> (FLOAT32_FRACTION_SIZE - FLOAT16_FRACTION_SIZE)) & 
                   ((1 << FLOAT16_FRACTION_SIZE) - 1);
// System.out.println("Exp16i=" + Long.toString(exp16,16));
// System.out.println("Fra16i=" + Long.toString(frac16,16));
           if (exp16 <= 0) {
               // Legal but unnormalized result
               frac16 +=(1 << FLOAT16_FRACTION_SIZE);
               frac16 >>= 1;
               while (exp16 < 0) {
                   frac16 >>= 1;
                   exp16++;
               }
           }
//System.out.println("Exp16=" + Long.toString(exp16,16));
// System.out.println("Fra16=" + Long.toString(frac16,16));
           bitFormat = 
               // Sign bit
               ((float32BitFormat >>> 32) & 0x8000) +
               // Exponent
               (exp16 << FLOAT16_FRACTION_SIZE) +
               // Fraction
               frac16;
//System.out.println("Tot=" + Long.toString(bitFormat,16));
        }
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.DOUBLE;
    }
    
    @Override
    byte[] internalEncode() throws IOException {
        int length = 2 << (headerTag - MT_FLOAT16) ;
        byte[] encoded = new byte[length];
        long integerRepresentation = bitFormat;
        int q = length;
        while (--q >= 0) {
            encoded[q] = (byte) integerRepresentation;
            integerRepresentation >>>= 8;
        }
        return ArrayUtil.add(new byte[]{headerTag}, encoded);
    }
    
    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.appendText(Double.toString(value));
    }
}
