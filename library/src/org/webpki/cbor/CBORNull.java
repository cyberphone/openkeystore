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

/**
 * Class for holding CBOR <code>null</code>.
 */
public class CBORNull extends CBORObject {

    static final byte[] NULL_TAG = {MT_NULL};

    /**
     * Creates a CBOR <code>null</code>.
     */
    public CBORNull() {}

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.NULL;
    }

    @Override
    byte[] internalEncode() throws IOException {
        return NULL_TAG;
    }

    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.append("null");
    }
}
