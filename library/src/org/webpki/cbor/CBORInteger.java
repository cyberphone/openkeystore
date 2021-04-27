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

/**
 * Class for holding CBOR integers.
 * 
 * Note that unsigned integers outside of the signed range must
 * use the {@link CBORInteger(long, boolean)} constructor! in order
 * to produce proper deterministic (canonical) encoding.
 */
public class CBORInteger extends CBORObject {

    private static final long serialVersionUID = 1L;

    long value;
    boolean forceUnsigned;
    boolean forceNegative;

    /**
     * Normal integer handling.
     * @param value
     */
    public CBORInteger(long value) {
        this(value, false);
    }
    
    /**
     * Force unsigned integer.
     * 
     * Since Java doesn't support unsigned integers, there is 
     * a need to use this constructor.  <code>0xffffffffffffffffL</code>
     * would in the standard constructor be considered as <code>-1</code>
     * which has a different encoding than the unsigned value.
     * @param value long value
     * @param forceUnsigned <code>true</code> if value should be considered as unsigned
     */
    public CBORInteger(long value, boolean forceUnsigned) {
        this.value = value;
        if (value == 0) {
            // -0 is not permitted
            forceNegative = false;
        }
        this.forceUnsigned = forceUnsigned;
    }

    @Override
    public CBORTypes getType() {
        return CBORTypes.INT;
    }

    @Override
    public byte[] encodeObject() throws IOException {
        return getEncodedCodedValue(
              (!forceNegative && (value >= 0 || forceUnsigned)) ? MT_UNSIGNED : MT_NEGATIVE, 
              value, 
              forceUnsigned,
              forceNegative);
    }
    
    BigInteger getBigIntegerRepresentation() {
        BigInteger bigInteger = BigInteger.valueOf(value);
        if (forceUnsigned) {
            bigInteger = bigInteger.and(CBORBigInteger.MAX_INT64);
        } else if (forceNegative) {
            bigInteger = bigInteger.and(CBORBigInteger.MAX_INT64).negate();
        }
        return bigInteger;
    }

    @Override
    StringBuilder internalToString(StringBuilder result) {
        return result.append(getBigIntegerRepresentation().toString());
    }
}
