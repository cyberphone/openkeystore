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

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>#7.n</code> (simple) objects.
 * <p>
 * Although <code>simple</code> types in the range of <code>0-19</code> and <code>32-255</code>
 * may appear like some kind of integers, serving as a limited set of <i>unique
 * and reserved labels</i> (keys) in CBOR maps seems like a more logical use case.
 * The <code>simple(99)</code> label featured in
 * <a href='../../webpki/cbor/doc-files/signatures.html' class='webpkilink'>Embedded&nbsp;Signatures</a>
 * is a representative example.
 * </p>
 */
public class CBORSimple extends CBORObject {

    int value;
    
    /**
     * Creates a CBOR <code>#7.n</code> (simple) object.
     * <p>
     * Simple values are limited to:
     * <code>0-23</code> and <code>32-255</code>.
     * </p>
     * @param value Value/type of simple
     * @throws CBORException
     * @see CBORObject#getSimple()
     */
    public CBORSimple(int value) {
        this.value = value;
        if (value < 0 || value > 255 || (value > 23 && value < 32)) {
            cborError(STDERR_SIMPLE_VALUE_OUT_OF_RANGE + value);
        }
    }

    @Override
    byte[] internalEncode() {
        return encodeTagAndN(MT_SIMPLE, value);
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append("simple(")
                   .append(String.valueOf(value))
                   .append(')');
    }

    static final String STDERR_SIMPLE_VALUE_OUT_OF_RANGE = 
        "Simple value out of range: " ;

}
