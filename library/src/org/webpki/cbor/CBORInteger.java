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

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR integers.
 */
public class CBORInteger extends CBORObject {

    private static final long serialVersionUID = 1L;

    long value;
    boolean forceUnsigned;

    /**
     * Normal integer handling.
     * @param value
     */
    CBORInteger(long value) {
        this(value, false);
    }
    
    /**
     * Force unsigned integer.
     * @param value
     * @param forceUnsigned
     */
    CBORInteger(long value, boolean forceUnsigned) {
        this.value = value;
        this.forceUnsigned = forceUnsigned;
    }
    
    @Override
    public CBORTypes getType() {
        return CBORTypes.INT;
    }

    @Override
    public byte[] writeObject() throws IOException {
        return getEncodedCodedValue(
                (value >= 0 || forceUnsigned) ? MT_UNSIGNED : MT_NEGATIVE, value, forceUnsigned);
    }

    @Override
    StringBuilder internalToString(StringBuilder result) {
        return result.append(value);
    }
}
