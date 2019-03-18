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

import java.math.*;

import org.webpki.util.DebugFormatter;


public final class ASN1Integer extends Simple {
    BigInteger value;

    public ASN1Integer(BigInteger value) {
        super(INTEGER, true);
        this.value = value;
    }

    public ASN1Integer(String value) {
        this(new BigInteger(value));
    }

    public ASN1Integer(long value) {
        this(Long.toString(value));
    }

    ASN1Integer(DerDecoder decoder) throws IOException {
        super(decoder, true);
        value = new BigInteger(decoder.content());
    }

    public void encode(Encoder encoder) throws IOException {
        byte[] content = value.toByteArray();
        encodeHeader(encoder, content.length, true);
        encoder.write(content);
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o) && ((ASN1Integer) o).value.equals(value);
    }

    public Object objValue() {
        return value();
    }

    public BigInteger value() {
        return value;
    }

    public int intValue() {
        return value.intValue();
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("INTEGER ");
        String num = value.toString();
        if (num.length() <= 10) {
            s.append(num);
        } else {
            num = DebugFormatter.getHexString(value.toByteArray());
            prefix = (num.length() <= 48) ? "" : "\n " + prefix + getByteNumberBlanks();
            while (num.length() > 0) {
                s.append(prefix);
                int i = 0;
                while (i < 32) {
                    if (i == num.length()) {
                        break;
                    }
                    if (i % 2 == 0) s.append(' ');
                    s.append(num.charAt(i++));
                }
                num = num.substring(i);
            }
        }
    }
}
