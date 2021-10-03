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

/**
 * Class for holding CBOR integers.
 * 
 * Note that unsigned integers outside of the signed range MUST
 * use the {@link CBORInteger(long, boolean)} or 
 * {@link CBORInteger(BigInteger)} constructors in order
 * to produce proper deterministic (canonical) encoding.
 */
public class CBORInteger extends CBORObject {

    long value;
    boolean unsignedMode;

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
        if (value < 0) {
            // Convert to magnitude mode
            this.value = ~value;
        } else {
            this.value = value;
            unsignedMode = true;
        }
    }
    
    /**
     * Force magnitude mode integer.
     * 
     * To cope with the entire 65-bit integer span supported by CBOR
     * you must use this constructor.  For unsigned integers values
     * from 0 to 2^64-1 can be specified while negative values range
     * from 1 to 2^64.  Examples:
     * <table>
     * <tr><th>Long&nbsp;Value</th><th>Unsigned&nbsp;Mode</th><th>Actual Value</th></tr>
     * <tr><td><code>0</code></td><td><code>true</code></td><td><code>0</code></td></tr>
     * <tr><td><code>0</code></td><td><code>false</code></td><td><code>-0x10000000000000000 (-2^64)</code></td></tr>
     * <tr><td><code>1</code></td><td><code>true</code></td><td><code>1</code></td></tr>
     * <tr><td><code>1</code></td><td><code>false</code></td><td><code>-1</code></td></tr>
     * <tr><td><code>0xffffffffffffffff</code></td><td><code>true</code></td><td><code>0xffffffffffffffff</code></td></tr>
     * <tr><td><code>0xffffffffffffffff</code></td><td><code>false</code></td><td><code>-0xffffffffffffffff</code></td></tr>
     * </table>
     *
     * @param value long value
     * @param unsignedMode <code>true</code> if value should be considered as unsigned
     */
    public CBORInteger(long value, boolean unsignedMode) {
        this.value = unsignedMode ? value : value - 1;
        this.unsignedMode = unsignedMode;
    }

    /**
     * Using BigInteger as input.
     * 
     * This constructor permits using the full range of applicable
     * integer values (-2^64 to 2^64-1).
     * 
     * @param value Integer in BigInteger format
     * @throws IllegalArgumentException If value does not fit a CBOR integer
     */
    public CBORInteger(BigInteger value) {
        if (!CBORBigInteger.fitsAnInteger(value)) {
                throw new IllegalArgumentException("Value out of range for " +
                                                   CBORInteger.class.getSimpleName());
        }
        if (value.compareTo(BigInteger.ZERO) >= 0) {
            this.value =  value.longValue();
            this.unsignedMode = true;
        } else {
            this.value =  value.add(BigInteger.ONE).negate().longValue();
        }
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.INTEGER;
    }

    @Override
    byte[] internalEncode() throws IOException {
        return getEncodedCore(unsignedMode ? MT_UNSIGNED : MT_NEGATIVE, value);
    }
    
    BigInteger returnAsBigInteger() {
        BigInteger bigInteger = BigInteger.valueOf(value).and(CBORBigInteger.MAX_INT64);
        if (unsignedMode) {
            return bigInteger;
        }
        return value == -1 ? CBORBigInteger.MIN_INT64 : bigInteger.add(BigInteger.ONE).negate();
    }

    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.appendText(returnAsBigInteger().toString());
    }
}
