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

/**
 * Class for holding CBOR integers.
 */
public class CBORInteger extends CBORObject {

    private static final long serialVersionUID = 1L;

    long value;
    boolean unsigned;

    CBORInteger(long value, boolean unsigned) {
        this.value = value;
        this.unsigned = unsigned;
    }
    
    CBORInteger(long value) {
        this(value, value >= 0);
    }

    @Override
    public CBORTypes getType() {
        return CBORTypes.INT;
    }

    @Override
    public byte[] writeObject() throws IOException {
        return new byte[] {6,7};
    }

    @Override
    StringBuilder internalToString() {
        return new StringBuilder().append(value);
    }
}
