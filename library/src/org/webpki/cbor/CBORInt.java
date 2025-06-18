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

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>int</code> objects.
 */
public class CBORInt extends CBORObject {

    static final BigInteger MAX_CBOR_INTEGER_MAGNITUDE = new BigInteger("ffffffffffffffff", 16);
    
    long value;
    boolean unsigned;
    
    /**
     * Creates a CBOR unsigned or negative <code>int</code> object.
     * <p>
     * Unsigned integers range from <code>0</code> to 
     * <span style='white-space:nowrap'><code>2<sup>64</sup>-1</code></span>,
     * while valid negative integers range from <code>-1</code> to
     * <span style='white-space:nowrap'><code>-2<sup>63</sup></code></span>.
     * </p>
     * <p>
     * See also {@link CBORBigInt#CBORBigInt(BigInteger)} and
     * {@link CBORObject#getBigInteger()}.
     * </p>
     *
     * @param value long value
     * @param unsigned <code>true</code> if value should be considered as unsigned
     * @throws CBORException
     */
    public CBORInt(long value, boolean unsigned) {
        this.value = value;
        this.unsigned = unsigned;
        if (!unsigned && value >= 0) {
            cborError(STDERR_INT_VALUE_OUT_OF_RANGE + value);
        }
    }

    /**
     * Creates a CBOR signed <code>int</code> object.
     * <p>
     * This constructor is equivalent to 
     * {@link CBORInt(long,boolean) <code>CBORInt(value, value >= 0)</code>}.
     * </p>
     * 
     * @param value Java (signed) long type
     */
    public CBORInt(long value) {
        this(value, value >= 0);
    }

    @Override
    byte[] internalEncode() {
        return encodeTagAndN(unsigned ? MT_UNSIGNED : MT_NEGATIVE, unsigned ? value : ~value);
    }

    BigInteger toBigInteger() {
        BigInteger bigInteger = BigInteger.valueOf(value);
        return unsigned ? bigInteger.and(MAX_CBOR_INTEGER_MAGNITUDE) : bigInteger;
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append(unsigned ? Long.toUnsignedString(value) : Long.toString(value));
    }

    static final String STDERR_INT_VALUE_OUT_OF_RANGE = "Integer out of range: ";

}
