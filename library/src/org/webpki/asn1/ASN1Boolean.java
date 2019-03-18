/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
package org.webpki.asn1;

import java.io.IOException;

public final class ASN1Boolean extends Simple {
    boolean value;

    public ASN1Boolean(boolean value) {
        super(BOOLEAN, true);
        this.value = value;
    }

    ASN1Boolean(DerDecoder decoder) throws IOException {
        // Boolean encoding shall be primitive
        super(decoder, true);

        if (decoder.length != 1) {
            throw new IOException("Boolean value must have length 1.");
        }
        value = decoder.content()[0] != 0;
    }

    public void encode(Encoder encoder) throws IOException {
        encode(encoder, value ? Encoder.TRUE : Encoder.FALSE);
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o) && ((ASN1Boolean) o).value == value;
    }

    public boolean value() {
        return value;
    }

    public Object objValue() {
        return new Boolean(value);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("BOOLEAN ").append(value);
    }
}
