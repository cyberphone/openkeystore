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

import java.util.ArrayList;

public final class CompositeContextSpecific extends Composite {
    public CompositeContextSpecific(int tagNumber, ArrayList<BaseASN1Object> components) {
        super(CONTEXT, tagNumber, components);
    }

    public CompositeContextSpecific(int tagNumber, BaseASN1Object[] components) {
        super(CONTEXT, tagNumber, components);
    }

    public CompositeContextSpecific(int tagNumber, BaseASN1Object value) {
        super(CONTEXT, tagNumber);
        components.add(value);
    }

    CompositeContextSpecific(DerDecoder decoder) {
        super(decoder);

        if (!isContext()) {
            throw new ASN1Exception("Internal error: Wrong tag class");
        }

        if (components == null) {
            throw new ASN1Exception("Empty CONTEXT_SPECIFIC.");
        }
    }

    public boolean sameType(BaseASN1Object o) {
        return o.getClass().equals(CompositeContextSpecific.class) &&
                o.tagNumber == tagNumber;
    }

    public boolean deepCompare(BaseASN1Object o) {
        if (!sameType(o) ||
                o.tagNumber != tagNumber || o.tagEncoding != tagEncoding) {
            return false;
        }
        CompositeContextSpecific cs = (CompositeContextSpecific) o;
        return ASN1Util.deepCompare(cs.components, components);
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("[").append(tagNumber).append("]");
        compositeString(s, prefix);
    }
}
