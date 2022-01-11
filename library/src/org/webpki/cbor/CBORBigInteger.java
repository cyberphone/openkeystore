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
 * Class for holding CBOR {@link BigInteger}.
 */
public class CBORBigInteger extends CBORObject {

    BigInteger value;
    
    static final BigInteger MAX_INT64 = new BigInteger("18446744073709551615");
    static final BigInteger MIN_INT64 = new BigInteger("-18446744073709551616");
    
    static final byte[] UNSIGNED_BIG_INTEGER_TAG = {MT_BIG_UNSIGNED};
    static final byte[] SIGNED_BIG_INTEGER_TAG   = {MT_BIG_SIGNED};
    
    /**
     * Create a CBOR <code>big number</code> object.
     * 
     * @param value
     */
    public CBORBigInteger(BigInteger value) {
        this.value = value;
        nullCheck(value);
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.BIG_INTEGER;
    }
    
    static boolean fitsAnInteger(BigInteger value) {
        return value.compareTo(MAX_INT64) <= 0 && value.compareTo(MIN_INT64) >= 0;
    }

    @Override
    byte[] internalEncode() throws IOException {
        if (fitsAnInteger(value)) {
            // Fits in "int65" decoding
            return new CBORInteger(value).internalEncode();
        }
        // Didn't fit "int65" so we must use big number decoding
        byte[] encoded;
        byte[] tag;
        if (value.compareTo(BigInteger.ZERO) >= 0) {
            encoded = value.toByteArray();
            tag = UNSIGNED_BIG_INTEGER_TAG;
        } else {
            encoded = value.negate().subtract(BigInteger.ONE).toByteArray();
            tag = SIGNED_BIG_INTEGER_TAG;
        }
        if (encoded[0] == 0) {
            // No leading zeroes please
            byte[] temp = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, temp, 0, temp.length);
            encoded = temp;
        }
        return ArrayUtil.add(tag, new CBORByteString(encoded).internalEncode());
    }
    
    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.appendText(value.toString());
    }
}
