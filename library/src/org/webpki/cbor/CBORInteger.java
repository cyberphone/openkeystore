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
 * Class for holding CBOR integer and big number.
 * 
 * Note that unsigned integers outside of the signed range MUST
 * use the {@link CBORInteger(long, boolean)} or 
 * {@link CBORInteger(BigInteger)} constructors in order
 * to produce proper deterministic (canonical) encoding.
 */
public class CBORInteger extends CBORObject {

    static final BigInteger MAX_INT64 = new BigInteger("18446744073709551615");
    static final BigInteger MIN_INT64 = new BigInteger("-18446744073709551616");
    
    static final byte[] UNSIGNED_BIG_INTEGER_TAG = {MT_BIG_UNSIGNED};
    static final byte[] SIGNED_BIG_INTEGER_TAG   = {MT_BIG_SIGNED};

    BigInteger value;
 
    /**
     * Standard integer handling.
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
     * Force magnitude mode integer.
     * 
     * To cope with the entire 65-bit integer span supported by CBOR
     * you must use this constructor.  For unsigned integers values
     * from 0 to 2^64-1 can be specified while negative values range
     * from 1 to 2^64.
     * <p>
     * If <code>unsigned</code> is set to <code>false</code>, this constructor
     * assumes CBOR native encoding mode.  That is, <code>value</code> is treated as
     * an unsigned magnitude offset by -1.  This means that the value 43 effectively
     * represents -44.  A special case is the value <code>0xffffffffffffffff</code>
     * (long -1), which corresponds to to -2^64.
     * </p>
     *
     * @param value long value
     * @param unsigned <code>true</code> if value should be considered as unsigned
     */
    public CBORInteger(long value, boolean unsigned) {
        this(unsigned ? 
            BigInteger.valueOf(value).and(MAX_INT64) 
                      : 
            value == -1 ? MIN_INT64 : BigInteger.valueOf(value)
                                          .and(MAX_INT64)
                                          .add(BigInteger.ONE)
                                          .negate());
    }

    /**
     * Using BigInteger as input.
     * 
     * This constructor permits using the full range of applicable
     * integer values.
     * 
     * @param value Integer in BigInteger format
     */
    public CBORInteger(BigInteger value) {
        this.value = value;
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
            return getEncodedCore(unsigned ? MT_UNSIGNED : MT_NEGATIVE, cborAdjusted.longValue());
        }
        // Does not fit "int65" so we must use big number decoding
        byte[] encoded = cborAdjusted.toByteArray();
        if (encoded[0] == 0) {
            // No leading zeroes please
            byte[] temp = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, temp, 0, temp.length);
            encoded = temp;
        }
        return ArrayUtil.add(unsigned ? UNSIGNED_BIG_INTEGER_TAG : SIGNED_BIG_INTEGER_TAG, 
                             new CBORByteString(encoded).internalEncode());
    }
    
    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.appendText(value.toString());
    }
}
