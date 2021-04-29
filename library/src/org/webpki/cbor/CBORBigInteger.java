/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
 * Class for holding CBOR {@link BigInteger}.
 */
public class CBORBigInteger extends CBORObject {

    private static final long serialVersionUID = 1L;

    BigInteger value;
    
    static final BigInteger MAX_INT64 = new BigInteger("18446744073709551615");
    static final BigInteger MIN_INT64 = new BigInteger("-18446744073709551616");
    
    static final byte[] UNSIGNED_BIG_INTEGER = {MT_BIG_UNSIGNED};
    static final byte[] SIGNED_BIG_INTEGER   = {MT_BIG_SIGNED};
    
    CBORBigInteger(BigInteger value) {
        this.value = value;
    }
    
    @Override
    public CBORTypes getType() {
        return CBORTypes.BIG_INTEGER;
    }

    @Override
    public byte[] encode() throws IOException {
        if (value.compareTo(MAX_INT64) <= 0 && value.compareTo(MIN_INT64) >= 0) {
            // Fits in "uint65" decoding
            if (value.compareTo(BigInteger.ZERO) >= 0) {
                return new CBORInteger(value.longValue(), true).encode();
            }
            return new CBORInteger(value.negate().longValue(), false).encode();
        }
        // Didn't fit "uint65" so we must use big number decoding
        byte[] encoded;
        byte[] headerTag;
        if (value.compareTo(BigInteger.ZERO) >= 0) {
            encoded = value.toByteArray();
            headerTag = UNSIGNED_BIG_INTEGER;
        } else {
            encoded = value.negate().subtract(BigInteger.ONE).toByteArray();
            headerTag = SIGNED_BIG_INTEGER;
        }
        if (encoded[0] == 0) {
            // No leading zeroes please
            byte[] temp = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, temp, 0, temp.length);
            encoded = temp;
        }
        return ArrayUtil.add(headerTag, new CBORByteArray(encoded).encode());
    }


    static BigInteger getValue(CBORObject cborObject) throws IOException {
        if (cborObject.getType() == CBORTypes.INT) {
            return ((CBORInteger) cborObject).getBigIntegerRepresentation();
        }
        cborObject.check(CBORTypes.BIG_INTEGER);
        return ((CBORBigInteger) cborObject).value;
    }
    
    @Override
    void internalToString(CBORObject initiator) {
        initiator.prettyPrint.append(value.toString());
    }
}
