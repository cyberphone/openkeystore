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
 * Class for holding CBOR big integers.
 */
public class CBORBigInteger extends CBORObject {

    private static final long serialVersionUID = 1L;

    BigInteger value;
    
    static final BigInteger MAX_INT64 = new BigInteger("18446744073709551615");
    static final BigInteger MIN_INT64 = new BigInteger("-18446744073709551616");
    
    CBORBigInteger(BigInteger value) {
        this.value = value;
    }
    
    @Override
    public CBORTypes getType() {
        return CBORTypes.BIG_INTEGER;
    }

    @Override
    public byte[] writeObject() throws IOException {
        if (value.compareTo(MAX_INT64) <= 0 && value.compareTo(MIN_INT64) >= 0) {
            CBORInteger cborInteger = new CBORInteger(value.longValue());
            // 65-bit integer emulation...
            if (value.compareTo(BigInteger.ZERO) >= 0) {
                cborInteger.forceUnsigned = true;
            } else {
                cborInteger.forceSigned = true;
            }
            return cborInteger.writeObject();
        }
        byte[] encoded;
        byte major;
        if (value.compareTo(BigInteger.ZERO) < 0) {
            encoded = value.negate().subtract(BigInteger.ONE).toByteArray();
            major = (byte) 0xc3;
        } else {
            encoded = value.toByteArray();
            major = (byte) 0xc2;
        }
        if (encoded[0] == 0) {
            byte[] temp = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, temp, 0, temp.length);
            encoded = temp;
        }
        return ArrayUtil.add(new byte[] {major}, new CBORByteArray(encoded).writeObject());
    }

    @Override
    StringBuilder internalToString(StringBuilder result) {
        return result.append(value.toString());
    }
}
