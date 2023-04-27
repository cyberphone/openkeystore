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
 * Class for holding CBOR <code>integer</code> objects.
 * <p>
 * Note that the encoder is adaptive, selecting the shortest possible
 * representation in order to produce a fully deterministic result.
 * </p>
 * <div id='recommendations' class='webpkicomment'>
 * Applications that are intended to work with multiple platforms
 * should for interoperability reasons not exploit {@link CBORInteger} numbers 
 * outside of the traditional range for <code>"unsigned"</code> and <code>"signed"</code> integers.
 * Translated to values, the <i>recommended</i> range would then span from
 * <span style='white-space:nowrap'><code>-2<div class='webpkisuper'>(n-1)</div></code></span> to
 * <span style='white-space:nowrap'><code>2<div class='webpkisuper'>n</div>-1</code></span>, 
 * where <code>n</code> is the size in bits of the anticipated target data type.
 * That is, if a protocol schema or declaration calls for a signed
 * <span style='white-space:nowrap'>32-bit</span> integer, the valid
 * range would be <code>-0x80000000</code> to <code>0x7fffffff</code>.
 * Note that these constraints do not apply to CBOR <code>integer</code>
 * objects that are <i>shorter</i> than the actual target data type.
 * Also see {@link CBORObject#getInt()}.
 * </div>
 */
public class CBORInteger extends CBORObject {

    static final byte[] UNSIGNED_INTEGER_TAG = {(byte)MT_UNSIGNED};
    static final byte[] NEGATIVE_INTEGER_TAG = {(byte)MT_NEGATIVE};
    
    static final BigInteger LONG_SIGN_BIT = new BigInteger("9223372036854775808");
    static final long LONG_UNSIGNED_PART  = 0x7fffffffffffffffl;
    
    long value;
    boolean unsigned;
    
    /**
     * Creates a CBOR unsigned or negative <code>integer</code>.
     * <p>
     * To cope with the entire 65-bit integer span supported by CBOR
     * you must use this constructor.  Unsigned integers
     * range from <code>0</code> to <code>2^64-1</code>,
     * while negative integers range from <code>-1</code> to <code>-2^64</code>.
     * </p>
     * <p>
     * If the <code>unsigned</code> flag is set to <code>false</code>, 
     * this constructor assumes CBOR native encoding mode for negative integers.
     * That is, <code>value</code> is treated as
     * an unsigned magnitude which is subsequently negated and subtracted by <code>1</code>.
     * This means that the input values <code>0</code>, <code>43</code>, 
     * and <code>-9223372036854775808L</code>,
     * actually represent <code>-1</code>, <code>-44</code>,
     * and <code>-9223372036854775809</code> respectively.
     * A special case is the value <code>0xffffffffffffffffL</code>
     * (long <code>-1</code>), which corresponds to <code>-2^64</code>.
     * </p>
     * Also see <a href='#recommendations'>recommendations</a>.
     *
     * @param value long value
     * @param unsigned <code>true</code> if value should be considered as unsigned
     */
    public CBORInteger(long value, boolean unsigned) {
        this.value = value;
        this.unsigned = unsigned;
    }

    /**
     * Creates a CBOR signed <code>integer</code> value.
     * <p>
 * Also see {@link CBORInteger(long, boolean)} and 
     * {@link CBORBigInteger#CBORBigInteger(BigInteger)}.
     * </p>
     * 
     * @param value Java (signed) long type
     */
    public CBORInteger(long value) {
        this(value >= 0 ? value : ~value, value >= 0);
    }
    
    @Override
    public CBORTypes getType() {
        return CBORTypes.INTEGER;
    }

    @Override
    public byte[] encode() {
        return encodeTagAndN(unsigned ? MT_UNSIGNED : MT_NEGATIVE, value);
    }

    BigInteger toBigInteger() {
        // "int65", really?!
        BigInteger bigInteger = BigInteger.valueOf(value & LONG_UNSIGNED_PART);
        if (value < 0) {
            bigInteger = bigInteger.add(LONG_SIGN_BIT);
        }
        return unsigned ? bigInteger : bigInteger.negate().subtract(BigInteger.ONE);
    }

    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
        cborPrinter.append(toBigInteger().toString());
    }
}
