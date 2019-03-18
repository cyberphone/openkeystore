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
import java.util.*;

import org.webpki.util.ArrayUtil;

public final class ASN1OctetString extends Binary {
    public ASN1OctetString(byte[] value) {
        super(OCTETSTRING, true, value);
    }

    ASN1OctetString(DerDecoder decoder) throws IOException {
        super(decoder);
        if (isPrimitive()) {
            value = decoder.content();
        } else {
            Vector<BaseASN1Object> v = readComponents(decoder);

            ASN1OctetString os;

            int length = 0;

            for (int i = 0; i < v.size(); i++) {
                length += ((ASN1OctetString) v.elementAt(i)).value.length;
            }

            value = new byte[length];

            int offset = 0;

            for (int i = 0; i < v.size(); i++) {
                os = (ASN1OctetString) v.elementAt(i);
                System.arraycopy(os.value, 0, value, offset, os.value.length);
                offset += os.value.length;
            }
        }
    }

    public void encode(Encoder encoder) throws IOException {
        encode(encoder, value);
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o) &&
                ArrayUtil.compare(((ASN1OctetString) o).value, value);
    }

    public String stringValue() {
        return new String(value);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("OCTET STRING, ");
        extractableStringData(s, prefix);
    }
}
