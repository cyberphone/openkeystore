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
 * <span style='white-space:nowrap'><code>-2<div class='webpkisuper'>(n-1)</div></code></span> to
 * <span style='white-space:nowrap'><code>2<div class='webpkisuper'>n</div>-1</code></span>, 
 * where <code>n</code> is the size in bits of the anticipated target integer type.
 * That is, if a protocol schema or declaration calls for a signed
 * <span style='white-space:nowrap'>32-bit</span> integer, the valid
 * range would be <code>-0x80000000</code> to <code>0x7fffffff</code>.
 * Note that range constraints do not apply to CBOR <code>integer</code>
 * numbers that are <i>shorter</i> than the actual target integer type.
 * Also see {@link CBORObject#getInt()}.
 * </div>
 */
public class CBORInt extends CBORObject {

    static final byte[] UNSIGNED_INTEGER_TAG = {(byte)MT_UNSIGNED};
    static final byte[] NEGATIVE_INTEGER_TAG = {(byte)MT_NEGATIVE};
    
    static final BigInteger LONG_SIGN_BIT = new BigInteger("9223372036854775808");
    static final long LONG_UNSIGNED_PART  = 0x7fffffffffffffffL;
    
    long value;
    boolean unsigned;
    
    /**
     * Creates a CBOR unsigned or negative <code>integer</code>.
     * <p>
     * </p>
     * To cope with the entire 65-bit integer span supported by CBOR,
     * this constructor must be used.  Unsigned integers
     * range from <code>0</code> to 
     * <span style='white-space:nowrap'><code>2<div class='webpkisuper'>64</div>-1</code></span>,
     * while negative integers range from <code>-1</code> to
     * <span style='white-space:nowrap'><code>-2<div class='webpkisuper'>64</div></code></span>.
     *<p>
     * </p> 
     * If the <code>unsigned</code> flag is set to <code>false</code>, 
     * this constructor assumes CBOR native encoding mode for negative integers.
     * That is, <code>value</code> is treated as
     * an unsigned magnitude which is subsequently negated and subtracted by <code>1</code>.
     * This means that the input values <code>0</code>, <code>9223372036854775807L</code>, 
     * <code>-9223372036854775808L</code>, and <code>-1</code>,
     * actually represent <code>-1</code>, <code>-9223372036854775808</code>,
     * <code>-9223372036854775809</code>, and
     * <code>-18446744073709551616</code>
     * (<span style='white-space:nowrap'><code>-2<div class='webpkisuper'>64</div></code></span>)
     * respectively.
     * <p>
     * Also see <a href='#range-constraints'>Range&nbsp;Constraints</a> and 
     * {@link CBORBigInt#CBORBigInt(BigInteger)}.
     * </p>
     *
     * @param value long value
     * @param unsigned <code>true</code> if value should be considered as unsigned
     */
    public CBORInt(long value, boolean unsigned) {
        super(CBORTypes.INTEGER);
        this.value = value;
        this.unsigned = unsigned;
    }

    /**
     * Creates a CBOR signed <code>integer</code> value.
     * <p>
     * Also see {@link CBORInt(long, boolean)} and 
     * {@link CBORBigInt#CBORBigInt(BigInteger)}.
     * </p>
     * 
     * @param value Java (signed) long type
     */
    public CBORInt(long value) {
        this(value >= 0 ? value : ~value, value >= 0);
    }

    @Override
    byte[] internalEncode() {
        return encodeTagAndN(unsigned ? MT_UNSIGNED : MT_NEGATIVE, value);
    }

    BigInteger toBigInteger() {
        // "int65", really?!
        BigInteger bigInteger = BigInteger.valueOf(value & LONG_UNSIGNED_PART);
        if (value < 0) {
            bigInteger = bigInteger.add(LONG_SIGN_BIT);
        }
        return unsigned ? bigInteger : bigInteger.not();
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append(toBigInteger().toString());
    }
}
