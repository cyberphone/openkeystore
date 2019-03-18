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

public final class ASN1Null extends Simple {
    public ASN1Null() {
        super(NULL, true);
    }

    ASN1Null(DerDecoder decoder) throws IOException {
        super(decoder);
        // Null has no content.
    }

    public void encode(Encoder encoder) throws IOException {
        // Null has no content. It shall be primitive.
        encodeHeader(encoder, 0, true);
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o);
    }

    public Object objValue() {
        return null;
    }

    public boolean diff(BaseASN1Object o, StringBuilder s, String prefix) {
        if (!sameType(o)) {
            s.append(prefix).append("<-------").append("    ");
            toString(s, prefix);
            s.append('\n');
            s.append(prefix).append("------->").append("    ");
            o.toString(s, prefix);
            s.append('\n');
            return true;
        }

        return false;
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("NULL");
    }
}
