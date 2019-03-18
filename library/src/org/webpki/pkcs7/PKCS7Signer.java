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
package org.webpki.pkcs7;

import java.io.IOException;

import java.util.Vector;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.SignerInterface;

import org.webpki.asn1.ASN1Util;
import org.webpki.asn1.ParseUtil;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.CompositeContextSpecific;
import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.ASN1Integer;
import org.webpki.asn1.ASN1OctetString;
import org.webpki.asn1.ASN1Set;
import org.webpki.asn1.ASN1ObjectID;
import org.webpki.asn1.ASN1Null;


public class PKCS7Signer {
    private AsymSignatureAlgorithms signatureAlgorithm = AsymSignatureAlgorithms.RSA_SHA1;

    private SignerInterface signer_implem;

    static final String PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2";

    static final String PKCS7_DATA = "1.2.840.113549.1.7.1";


    public void setSignatureAlgorithm(AsymSignatureAlgorithms signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }


    private byte[] sign(byte[] message, boolean detached) throws IOException {
        try {
            Vector<BaseASN1Object> cert_path = new Vector<BaseASN1Object>();
            for (X509Certificate c : signer_implem.getCertificatePath()) {
                cert_path.add(ASN1Util.x509Certificate(c));
            }

            BaseASN1Object signer_cert = cert_path.elementAt(0);

            int i = ParseUtil.isContext(signer_cert.get(new int[]{0, 0}), 0) ? 1 : 0;

            BaseASN1Object sign_info = signer_cert.get(new int[]{0, i + 2});
            BaseASN1Object cert_ref = signer_cert.get(new int[]{0, i});

            String digest_oid = signatureAlgorithm.getDigestAlgorithm().getOID();
            String encryption_oid = AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5.getOid();

            byte[] signed_data = signer_implem.signData(message, signatureAlgorithm);

            BaseASN1Object r =
                    ASN1Util.oidValue(PKCS7_SIGNED_DATA,
                            new CompositeContextSpecific(0,
                                    new ASN1Sequence(new BaseASN1Object[]{
                                            new ASN1Integer(1),
                                            ASN1Util.oidValueSet(digest_oid, new ASN1Null()),
                                            detached ?
                                                    new ASN1Sequence((BaseASN1Object) new ASN1ObjectID(PKCS7_DATA)) :
                                                    (BaseASN1Object) ASN1Util.oidValue(PKCS7_DATA,
                                                            new CompositeContextSpecific(0, new ASN1OctetString(message))
                                                    ),
                                            new CompositeContextSpecific(0, cert_path),
                                            new ASN1Set(
                                                    new ASN1Sequence(new BaseASN1Object[]{
                                                            new ASN1Integer(1),
                                                            new ASN1Sequence(new BaseASN1Object[]{sign_info, cert_ref}),
                                                            ASN1Util.oidNull(digest_oid),
                                                            ASN1Util.oidNull(encryption_oid),
                                                            new ASN1OctetString(signed_data)
                                                    })
                                            )
                                    })
                            )
                    );
            return r.encode();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    /**
     * Signs a message.
     * <p>Creates a detached (not containing the actual data signed) PKCS#7 SignedData message.
     *
     * @param message the message to be signed.
     * @return DER-encoded PKCS#7 SignedData message.
     * @throws IOException If something unexpected happens...
     */
    public byte[] signDetachedMessage(byte message[]) throws IOException {
        return sign(message, true);
    }

    /**
     * Signs a message.
     * <p>Creates a PKCS#7 SignedData message.
     *
     * @param message the message to be signed.
     * @return DER-encoded PKCS#7 SignedData message.
     * @throws IOException If something unexpected happens...
     */
    public byte[] signMessage(byte message[]) throws IOException {
        return sign(message, false);
    }

    /**
     * Creates an PKCS7Signer using the given {@link SignerInterface SignerInterface}.
     *
     * @param signer The signer
     */
    public PKCS7Signer(SignerInterface signer) {
        this.signer_implem = signer;
    }

}
