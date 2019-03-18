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
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.cert.*;

public class ASN1Sequence extends Composite {
    public ASN1Sequence(BaseASN1Object[] components) {
        super(SEQUENCE, components);
    }

    public ASN1Sequence(Vector<BaseASN1Object> components) {
        super(SEQUENCE, components);
    }

    public ASN1Sequence(BaseASN1Object component) {
        super(SEQUENCE, new BaseASN1Object[]{component});
    }

    ASN1Sequence(DerDecoder decoder) throws IOException {
        super(decoder);
    }

    /*
     * Try to construct a X509Certificate from this sequence.
     */
    public X509Certificate x509Certificate()
            throws IOException, GeneralSecurityException {
        // TODO !!!!!! This should be changed (moved and used more generally).
        if (blob == null) {
            blob = encode();
            blobOffset = 0;
        }

        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(blob, blobOffset, blob.length - blobOffset));
    }

    void toString(StringBuilder s, String prefix) {
        s.append(getByteNumber()).append(prefix).append("SEQUENCE");
        compositeString(s, prefix);
    }
}
