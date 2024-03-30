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

import org.webpki.crypto.CertificateUtil;

import java.security.cert.X509Certificate;

public class ASN1Util {
    public final static ASN1Null STATIC_NULL = new ASN1Null();
    public final static ASN1Boolean STATIC_TRUE = new ASN1Boolean(true);
    public final static ASN1Boolean STATIC_FALSE = new ASN1Boolean(false);

    static boolean deepCompare(ArrayList<BaseASN1Object> a, ArrayList<BaseASN1Object> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (int i = 0; i < a.size(); i++) {
            if (!(a.get(i)).deepCompare(b.get(i))) {
                return false;
            }
        }
        return true;
    }

    public static byte[] getBinary(BaseASN1Object o, int[] path) {
        return ((Binary) o.get(path)).value();
    }

    public static X509Certificate x509Certificate(BaseASN1Object o, int[] path) {
        return ParseUtil.sequence(o.get(path)).x509Certificate();
    }

    public static X509Certificate x509Certificate(BaseASN1Object o) {
        return ParseUtil.sequence(o).x509Certificate();
    }

    public static ASN1Sequence x509Certificate(X509Certificate c) {
        return ParseUtil.sequence(new DerDecoder(
                CertificateUtil.getBlobFromCertificate(c)).readNext());
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
