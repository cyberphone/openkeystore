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

public class ASN1T61String extends ASN1String {
    ASN1T61String(String value) {
        super(T61STRING, value);
    }

    ASN1T61String(DerDecoder decoder) throws IOException {
        super(decoder);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("T61String '").append(value()).append('\'');
    }
}
