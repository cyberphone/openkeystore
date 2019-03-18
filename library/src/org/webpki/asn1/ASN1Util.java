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

import java.util.*;
import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.io.*;

public class ASN1Util {
    public final static ASN1Null STATIC_NULL = new ASN1Null();
    public final static ASN1Boolean STATIC_TRUE = new ASN1Boolean(true);
    public final static ASN1Boolean STATIC_FALSE = new ASN1Boolean(false);

    static boolean deepCompare(Vector<BaseASN1Object> a, Vector<BaseASN1Object> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (int i = 0; i < a.size(); i++) {
            if (!(a.elementAt(i)).deepCompare(b.elementAt(i))) {
                return false;
            }
        }
        return true;
    }

    public static byte[] getBinary(BaseASN1Object o, int[] path) throws IOException {
        return ((Binary) o.get(path)).value();
    }

    public static X509Certificate x509Certificate(BaseASN1Object o, int[] path)
            throws IOException, GeneralSecurityException {
        return ParseUtil.sequence(o.get(path)).x509Certificate();
    }

    public static X509Certificate x509Certificate(BaseASN1Object o)
            throws IOException, GeneralSecurityException {
        return ParseUtil.sequence(o).x509Certificate();
    }

    public static ASN1Sequence x509Certificate(Certificate c)
            throws IOException, GeneralSecurityException {
        return ParseUtil.sequence(new DerDecoder(c.getEncoded()).readNext());
    }

    public static ASN1Sequence oidValue(String oid, BaseASN1Object value) {
        return new ASN1Sequence(new BaseASN1Object[]{new ASN1ObjectID(oid), value});
    }

    public static ASN1Sequence oidNull(String oid) {
        return new ASN1Sequence(new BaseASN1Object[]{new ASN1ObjectID(oid), STATIC_NULL});
    }

    public static ASN1Set oidValueSet(String oid, BaseASN1Object value) {
        return new ASN1Set(new ASN1Sequence(new BaseASN1Object[]{new ASN1ObjectID(oid), value}));
    }
}
