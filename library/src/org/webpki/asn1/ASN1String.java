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
package org.webpki.asn1;

import java.util.*;

public abstract class ASN1String extends Simple {
    byte[] value;

    ASN1String(int tagNumber, byte[] value) {
        super(tagNumber, true);
        this.value = value;
    }

    ASN1String(int tagNumber, String value) {
        super(tagNumber, true);
        this.value = value.getBytes();
    }

    ASN1String(DerDecoder decoder) {
        super(decoder);

        if (isPrimitive()) {
            value = decoder.content();
        } else {
            ArrayList<BaseASN1Object> subParts = readComponents(decoder);
            int length = 0;

            for (BaseASN1Object e : subParts) {
                length += ((ASN1OctetString) e).value.length;
            }

            value = new byte[length];

            int o = 0;

            for (BaseASN1Object e : subParts) {
                byte[] t = ((ASN1OctetString) e).value;
                System.arraycopy(t, 0, value, o, t.length);
                o += t.length;
            }
        }
    }

    public String value() {
        return new String(value);
    }

    public Object objValue() {
        return value();
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o) && ((ASN1String) o).value.equals(value);
    }

    public void encode(Encoder encoder) {
        // Use primitive encoding.
        encodeHeader(encoder, value.length);
        encoder.write(value);
    }
}
