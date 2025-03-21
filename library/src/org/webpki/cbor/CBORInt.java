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
 * Class for holding CBOR <code>integer</code> objects.
 * <p id='range-constraints'>
 * Note that the encoder is adaptive, selecting the shortest possible
 * representation in order to produce a fully deterministic result.
 * </p>
 * <div class='webpkicomment'>
 * Applications that are intended to work with multiple platforms
 * should for interoperability reasons not exploit CBOR <code>integer</code> numbers 
 * outside of the traditional range for <code>"unsigned"</code> and <code>"signed"</code> integers.
 * Translated to values, the <i>recommended</i> range would then span from
 * <span style='white-space:nowrap'><code>-2<sup>(n-1)</sup></code></span> to
 * <span style='white-space:nowrap'><code>2<sup>n</sup>-1</code></span>, 
 * where <code>n</code> is the size in bits of the anticipated target integer type.
 * That is, if a protocol schema or declaration calls for a signed
 * <span style='white-space:nowrap'>32-bit</span> integer, the valid
 * range would be <code>-0x80000000</code> to <code>0x7fffffff</code>.
 * See also {@link CBORObject#getInt32()}.
 * </div>
 */
public class CBORInt extends CBORObject {
    
    long value;
    boolean unsigned;
    
    /**
     * Creates a CBOR unsigned or negative <code>integer</code>.
     * <p>
     * This constructor must be used for all integers. Unsigned integers
     * range from <code>0</code> to 
     * <span style='white-space:nowrap'><code>2<sup>64</sup>-1</code></span>,
     * while valid negative integers range from <code>-1</code> to
     * <span style='white-space:nowrap'><code>-2<sup>63</sup></code></span>.
     * </p>
     * <p>
     * See also <a href='#range-constraints'>Range&nbsp;Constraints</a> and 
     * {@link CBORBigInt#CBORBigInt(BigInteger)}.
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
     * Creates a CBOR signed <code>integer</code>.
     * <p>
     * See also {@link CBORInt(long, boolean)} and 
     * {@link CBORBigInt#CBORBigInt(BigInteger)}.
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
