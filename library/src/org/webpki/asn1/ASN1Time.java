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

public abstract class ASN1Time extends Simple {
    Date value;

    ASN1Time(DerDecoder decoder) throws IOException {
        super(decoder);
    }

    ASN1Time(int tagNumber, Date value) {
        super(tagNumber, false);
        this.value = value;
    }

    public Date value() {
        return value;
    }

    public Object objValue() {
        return value();
    }

    abstract String encodedForm();

    public void encode(Encoder encoder) throws IOException {
        String encodedForm = encodedForm();
        encodeHeader(encoder, encodedForm.length(), true);
        encoder.write(encodedForm.getBytes());
    }
}
