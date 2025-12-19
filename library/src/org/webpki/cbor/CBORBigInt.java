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

import java.math.BigInteger;

import java.util.Arrays;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>integer</code> objects.
 * @see CBORInt
 */
public class CBORBigInt extends CBORObject {

    static final byte[] UNSIGNED_BIGNUM_TAG = {(byte)MT_BIG_UNSIGNED};
    static final byte[] NEGATIVE_BIGNUM_TAG = {(byte)MT_BIG_NEGATIVE};

    BigInteger value;
 
    /**
     * Creates a CBOR <code>integer</code> value of any size.
     * <p>
     * Note: if <code>value</code> is within the CBOR <code>int</code> range,
     * <code>int</code> encoding will be used, otherwise <code>value</code>
     * will be encoded as a CBOR <code>bigint</code>.
     * </p>
     * @see CBORInt#CBORInt(long)
     * @see CBORObject#getBigInteger()
     * @param value Integer in BigInteger format
     */
    public CBORBigInt(BigInteger value) {
        this.value = value;
        nullCheck(value);
    }
    
    @Override
    byte[] internalEncode() {
        boolean unsigned = value.compareTo(BigInteger.ZERO) >= 0;
        BigInteger cborAdjusted = unsigned ? value : value.not();
        byte[] encoded = cborAdjusted.toByteArray();
        if (encoded[0] == 0) {
            // Remove leading zero which may be present due to two-complement encoding.
            encoded = Arrays.copyOfRange(encoded, 1, encoded.length);
        }
        if (encoded.length <= 8) {
            // Fits "int" encoding.
            return encodeTagAndN(unsigned ? MT_UNSIGNED : MT_NEGATIVE, cborAdjusted.longValue());
        }
        // Needs "bigint" encoding.
        return CBORUtil.concatByteArrays(unsigned ? UNSIGNED_BIGNUM_TAG : NEGATIVE_BIGNUM_TAG, 
                                         new CBORBytes(encoded).encode());
    }
    
    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append(value.toString());
    }
}
