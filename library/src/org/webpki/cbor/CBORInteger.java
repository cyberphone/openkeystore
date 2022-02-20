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

import java.math.BigInteger;

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR <code>integer</code> and <code>big number</code>.
 * 
 * Note that the encoder is adaptive, selecting the shortest possible
 * representation in order to produce a fully deterministic result.
 */
public class CBORInteger extends CBORObject {

    static final BigInteger MAX_INT64 = new BigInteger("18446744073709551615");
    static final BigInteger MIN_INT64 = new BigInteger("-18446744073709551616");
    
    static final byte[] UNSIGNED_BIG_INTEGER_TAG = {MT_BIG_UNSIGNED};
    static final byte[] SIGNED_BIG_INTEGER_TAG   = {MT_BIG_SIGNED};

    BigInteger value;
 
    /**
     * Create a CBOR <code>integer</code>.
     * <p>
     * Note: this constructor assumes that value is a <i>signed</i> long.
     * </p>
     * See {@link CBORInteger(long, boolean)}.
     * 
     * @param value Integer in long format
      */
    public CBORInteger(long value) {
        this(BigInteger.valueOf(value));
    }
    
    /**
     * Create a CBOR <code>unsigned</code> or <code>negative integer</code>.
     * 
     * To cope with the entire 65-bit integer span supported by CBOR
     * you must use this constructor.  Unsigned integers
     * range from <code>0</code> to <code>2^64-1</code>,
     * while negative integers range from <code>-1</code> to <code>-2^64</code>.
     * <p>
     * If the <code>unsigned</code> flag is set to <code>false</code>, this constructor
     * assumes CBOR native encoding mode for negative integers.  That is, <code>value</code> is treated as
     * an unsigned magnitude which is subsequently negated and subtracted by <code>1</code>.
     * This means that the input values <code>0</code>, <code>43</code>, and <code>-9223372036854775808L</code>,
     * actually represent <code>-1</code>, <code>-44</code>, and <code>-9223372036854775809</code> respectively.
     * A special case is the value <code>0xffffffffffffffffL</code>
     * (long <code>-1</code>), which corresponds to <code>-2^64</code>.
     * </p>
     * See {@link CBORInteger(long)} and {@link #CBORInteger(BigInteger)}.
     *
     * @param value long value
     * @param unsigned <code>true</code> if value should be considered as unsigned
     */
    public CBORInteger(long value, boolean unsigned) {
        this(unsigned ? 
            BigInteger.valueOf(value).and(MAX_INT64) 
                      : 
            BigInteger.valueOf(value).and(MAX_INT64).add(BigInteger.ONE).negate());
    }

    /**
     * Creates a CBOR integer value of any size.
     * <p>
     * If <code>value</code> is within the CBOR <code>integer</code> range,
     * the <code>integer</code> type will be used, otherwise serializations
     * will use the <code>big&nbsp;number</code> type.
     * </p>
     * 
     * @param value Integer in BigInteger format
     */
    public CBORInteger(BigInteger value) {
        this.value = value;
        nullCheck(value);
    }

    static boolean fitsAnInteger(BigInteger value) {
        return value.compareTo(MAX_INT64) <= 0 && value.compareTo(MIN_INT64) >= 0;
    }
    
    @Override
    CBORTypes internalGetType() {
        return CBORTypes.INTEGER;
    }

    @Override
    byte[] internalEncode() throws IOException {
        boolean unsigned = value.compareTo(BigInteger.ZERO) >= 0;
        BigInteger cborAdjusted = unsigned ? value : value.negate().subtract(BigInteger.ONE);
        if (fitsAnInteger(value)) {
            // Fits in "int65" decoding
            return encodeTagAndN(unsigned ? MT_UNSIGNED : MT_NEGATIVE, cborAdjusted.longValue());
        }
        // Does not fit "int65" so we must use big number encoding
        byte[] encoded = cborAdjusted.toByteArray();
        if (encoded[0] == 0) {
            // Drop possible leading zero
            byte[] temp = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, temp, 0, temp.length);
            encoded = temp;
        }
        return ArrayUtil.add(unsigned ? UNSIGNED_BIG_INTEGER_TAG : SIGNED_BIG_INTEGER_TAG, 
                             new CBORByteString(encoded).internalEncode());
    }
    
    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
        cborPrinter.append(value.toString());
    }
}
