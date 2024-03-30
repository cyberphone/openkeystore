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

import java.util.Arrays;

public final class SimpleContextSpecific extends Binary {
    public SimpleContextSpecific(int tagNumber, byte[] value) {
        super(CONTEXT, tagNumber, true, value);
        this.value = new byte[value.length];
        System.arraycopy(value, 0, this.value, 0, value.length);
    }

    public SimpleContextSpecific(int tagNumber, BaseASN1Object value) {
        this(tagNumber, value.encodeContent());
    }

    SimpleContextSpecific(DerDecoder decoder) {
        super(decoder);

        if (!isContext()) {
            throw new ASN1Exception("Internal error: Wrong tag class");
        }

        if (isPrimitive()) {
            value = decoder.content();
        } else {
            throw new ASN1Exception("Internal error: Composite");
        }

        if (value == null) {
            throw new ASN1Exception("Empty CONTEXT_SPECIFIC.");
        }
    }

    public byte value(int i) {
        return value[i];
    }

    public void encode(Encoder encoder) {
        encode(encoder, value);
    }

    public boolean sameType(BaseASN1Object o) {
        return o.getClass().equals(SimpleContextSpecific.class) &&
                o.tagNumber == tagNumber;
    }

    public boolean diff(BaseASN1Object o, StringBuilder s, String prefix) {
        throw new Error("kex");
    }

    public boolean deepCompare(BaseASN1Object o) {
        if (!sameType(o) ||
                o.tagNumber != tagNumber || o.tagEncoding != tagEncoding) {
            return false;
        }

        SimpleContextSpecific cs = (SimpleContextSpecific) o;
        return Arrays.equals(cs.value, value);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("[").append(tagNumber).append("], ").append(value.length).append(" bytes");
        hexData(s, value);
    }
}
