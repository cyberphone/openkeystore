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

import java.math.BigInteger;

/**
 * Class for holding CBOR <code>big&nbsp;integer</code> objects.
 * <p>
 * Note that the encoder is adaptive, selecting the shortest possible
 * representation in order to produce a fully deterministic result.
 * </p>
 */
public class CBORBigInt extends CBORObject {

    static final byte[] UNSIGNED_BIG_INTEGER_TAG = {(byte)MT_BIG_UNSIGNED};
    static final byte[] NEGATIVE_BIG_INTEGER_TAG = {(byte)MT_BIG_NEGATIVE};

    BigInteger value;
 
    /**
     * Creates a CBOR integer value of any size.
     * <p>
     * Note: if the <code>value</code> is within the CBOR <code>integer</code> range,
     * <code>integer</code> encoding will be used, otherwise the <code>value</code>
     * will be encoded as a CBOR <code>big&nbsp;integer</code>.
     * </p>
     * 
     * @param value Integer in BigInteger format
     */
    public CBORBigInt(BigInteger value) {
        this.value = value;
        nullCheck(value);
    }
    
    @Override
    public CBORTypes getType() {
        return CBORTypes.BIG_INTEGER;
    }

    @Override
    public byte[] encode() {
        boolean unsigned = value.compareTo(BigInteger.ZERO) >= 0;
        BigInteger cborAdjusted = unsigned ? value : value.negate().subtract(BigInteger.ONE);
        byte[] encoded = cborAdjusted.toByteArray();
        if (encoded[0] == 0) {
            // Remove leading zero which may be present due to two-complement encoding.
            byte[] temp = new byte[encoded.length - 1];
            System.arraycopy(encoded, 1, temp, 0, temp.length);
            encoded = temp;
        }
        if (encoded.length <= 8) {
            // Fits in "int65" decoding.
            return new CBORInt(cborAdjusted.longValue(), unsigned).encode();
        }
        // Does not fit "int65" so we must use big integer encoding.
        return addByteArrays(unsigned ? UNSIGNED_BIG_INTEGER_TAG : NEGATIVE_BIG_INTEGER_TAG, 
                             new CBORBytes(encoded).encode());
    }
    
    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
        cborPrinter.append(value.toString());
    }
}
