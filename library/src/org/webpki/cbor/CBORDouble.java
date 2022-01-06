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
    
    int headerTag = MT_FLOAT16;
    long bitFormat;
    
    static final int NOT_A_NUMBER      = 0x7e00;
    static final int NEGATIVE_INFINITY = 0xfc00;
    static final int POSITIVE_INFINITY = 0x7c00;
    static final int NEGATIVE_ZERO     = 0xfc00;
    static final int POSITIVE_ZERO     = 0x7c00;
    
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
        if (bitFormat == 0x7ff8000000000000l) {
            bitFormat = NOT_A_NUMBER;
        } else if (bitFormat == 0x7ff0000000000000l) {
            bitFormat = POSITIVE_INFINITY;
        } else if (bitFormat == 0xfff0000000000000l) {
            bitFormat = NEGATIVE_INFINITY;
        } else if (bitFormat == 0x0000000000000000l) {
            bitFormat = POSITIVE_ZERO;
        } else if (bitFormat == 0x8000000000000000l) {
            bitFormat = NEGATIVE_ZERO;
        } else if (positiveValue > Float.MAX_VALUE || 
                   (bitFormat & ((1 << (FLOAT64_FRACTION_SIZE - FLOAT32_FRACTION_SIZE)) - 1)) != 0) {
            headerTag = MT_FLOAT64; 
        } else if (positiveValue > MAX_HALF_FLOAT ||
                   (bitFormat & ((1 << (FLOAT64_FRACTION_SIZE - FLOAT16_FRACTION_SIZE)) - 1)) != 0) {
            headerTag = MT_FLOAT32;
            bitFormat = Float.floatToIntBits((float)value);
        } else {
            bitFormat = 
                // Sign bit
                ((bitFormat >>> 48) & 0x8000) +
                // Exponent
                (((bitFormat >>> (FLOAT64_FRACTION_SIZE - FLOAT16_FRACTION_SIZE)) &
                   ((1 << FLOAT16_FRACTION_SIZE + FLOAT64_EXPONENT_SIZE) - 1)) +
                   (FLOAT16_EXPONENT_BIAS - FLOAT64_EXPONENT_BIAS) << FLOAT16_FRACTION_SIZE) +
                // Fraction
                ((bitFormat >>> (FLOAT64_FRACTION_SIZE - FLOAT16_FRACTION_SIZE)) & 
                   ((1 << FLOAT16_FRACTION_SIZE) - 1));
        }
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.DOUBLE;
    }
    
    @Override
    byte[] internalEncode() throws IOException {
        int length = 2 << (headerTag - (MT_FLOAT16 & 0xff));
        byte[] encoded = new byte[length];
        long integerRepresentation = bitFormat;
        int q = length;
        while (--q >= 0) {
            encoded[q] = (byte) integerRepresentation;
            integerRepresentation >>>= 8;
        }
        return ArrayUtil.add(new byte[]{(byte)headerTag}, encoded);
    }
    
    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.appendText(Double.toString(value));
    }
}
