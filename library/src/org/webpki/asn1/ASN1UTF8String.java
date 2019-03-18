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
import java.io.UnsupportedEncodingException;

public class ASN1UTF8String extends ASN1String {
    public ASN1UTF8String(String value) { // throws UnsupportedEncodingException
        super(UTF8STRING, getBytesUTF8(value));
    }

    ASN1UTF8String(DerDecoder decoder) throws IOException {
        super(decoder);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("UTF8String '").append(value()).append('\'');
    }

    private static byte[] getBytesUTF8(String value) {
        try {
            return value.getBytes("UTF-8");
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("UTF-8 not supported!");
        }

    }

    public String value() {
        try {
            return new String(value, "UTF-8");
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("UTF-8 not supported!");
        }
    }
}
