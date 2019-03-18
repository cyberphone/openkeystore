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

import java.math.BigInteger;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.VerifierInterface;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.asn1.ASN1Util;
import org.webpki.asn1.ParseUtil;
import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.Composite;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.CompositeContextSpecific;
import org.webpki.asn1.ASN1Sequence;

import org.webpki.asn1.cert.DistinguishedName;


public class PKCS7Verifier {
    private X509Certificate[] certpath;

    private VerifierInterface verifier_interface;

    private HashAlgorithms digest_algorithm;

    private byte[] message;

    private SignerInfo signer_info;

    class IssuerAndSerialNumber {
        DistinguishedName issuer;

        BigInteger serial;

        IssuerAndSerialNumber(BaseASN1Object issuer_and_serial) throws IOException {
            ASN1Sequence seq = ParseUtil.sequence(issuer_and_serial, 2);

            issuer = new DistinguishedName(seq.get(0));

            serial = ParseUtil.integer(seq.get(1)).value();
        }

        IssuerAndSerialNumber(X509Certificate certificate) throws IOException, GeneralSecurityException {
            ASN1Sequence seq = ASN1Util.x509Certificate(certificate);

            issuer = DistinguishedName.issuerDN(seq);

            seq = ParseUtil.sequence(seq.get(0));

            serial = ParseUtil.integer(seq.get(ParseUtil.isContext(seq.get(0), 0) ? 1 : 0)).value();
        }

        boolean matches(X509Certificate certificate) throws IOException, GeneralSecurityException {
            IssuerAndSerialNumber t = new IssuerAndSerialNumber(certificate);
            //System.out.println("SSSSSSSSSS " + serial + " --- " + t.serial);
            return issuer.equals(t.issuer) && serial.equals(t.serial);
        }

    }


    private class SignerInfo {
        private IssuerAndSerialNumber issuer_and_serial;

        private byte[] encrypted_digest;


        SignerInfo(BaseASN1Object signerInfo) throws IOException {
            ASN1Sequence seq = ParseUtil.sequence(signerInfo);

            if (ParseUtil.integer(seq.get(0)).intValue() > 2) {
                throw new IOException("Version > 2");
            }

            issuer_and_serial = new IssuerAndSerialNumber(seq.get(1));

            if (HashAlgorithms.getAlgorithmFromOid(getAlgorithmIdentifier(seq.get(2))) != digest_algorithm) {
                throw new IOException("Inconsistent digest algorithms");
            }

            int i = 3;

            if (seq.get(i) instanceof CompositeContextSpecific) {
                throw new IOException("Authenticated not supported");
            }

            if (AsymEncryptionAlgorithms.getAlgorithmFromOid(getAlgorithmIdentifier(seq.get(i++))) != AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5) {
                throw new IOException("Only RSA is supported by this implementation");
            }

            encrypted_digest = ParseUtil.octet(seq.get(i++));

            if (seq.size() > i) {
                throw new IOException("Unauthenticated not supported");
            }
        }

    }


    private class SignedData {

        SignedData(BaseASN1Object signed_data, byte detached_data[]) throws IOException, GeneralSecurityException {
            ASN1Sequence contents;

            try {
                ASN1Sequence top = ParseUtil.sequence(signed_data, 2);

                ParseUtil.oid(top.get(0), PKCS7Signer.PKCS7_SIGNED_DATA);

                contents = ParseUtil.sequence(ParseUtil.compositeContext(top.get(1), 0, 1).get(0));
            } catch (IOException tme) {
                contents = ParseUtil.sequence(signed_data);
            }

            ParseUtil.integer(contents.get(0), 1);

            digest_algorithm = HashAlgorithms.getAlgorithmFromOid(getAlgorithmIdentifier(ParseUtil.set(contents.get(1), 1).get(0)));

            if (detached_data != null) {
                message = detached_data;
                ParseUtil.oid(ParseUtil.sequence(contents.get(2), 1).get(0), PKCS7Signer.PKCS7_DATA);
            } else {
                message = ParseUtil.octet(ParseUtil.compositeContext(ParseUtil.seqOIDValue(contents.get(2), PKCS7Signer.PKCS7_DATA), 0, 1).get(0));
            }

            int index = 3;

            CompositeContextSpecific certs = ParseUtil.compositeContext(contents.get(index), new int[]{0, 2});
            index++;

            // Get certificates
            certpath = new X509Certificate[certs.size()];
            for (int i = 0; i < certs.size(); i++) {
                certpath[i] = ParseUtil.sequence(certs.get(i)).x509Certificate();
            }
            certpath = CertificateUtil.getSortedPath(certpath);

            try {
                ParseUtil.compositeContext(contents.get(index), new int[]{1, 3});
                throw new IOException("CRLs not supported");
            } catch (IOException tme) {
                // Assume the file contained no CRLs.
            }

            Composite signer_infos = ParseUtil.setOrSequence(contents.get(index));
            if (signer_infos.size() > 1) {
                throw new IOException("Only one signature supported");
            }
            signer_info = new SignerInfo(ParseUtil.sequence(signer_infos.get(0)));
        }

        SignedData(BaseASN1Object signed_data) throws IOException, GeneralSecurityException {
            this(signed_data, null);
        }
    }


    static String getAlgorithmIdentifier(BaseASN1Object o) throws IOException {
        return ParseUtil.oid(ParseUtil.sequence(o).get(0)).oid();
    }


    private void verify() throws IOException, GeneralSecurityException {
        if (!signer_info.issuer_and_serial.matches(certpath[0])) {
            throw new IOException("Signer certificate descriptor error");
        }
        if (!new SignatureWrapper(getSignatureAlgorithm(), certpath[0].getPublicKey())
                .setEcdsaSignatureEncoding(true)
                .update(message)
                .verify(signer_info.encrypted_digest)) {
            throw new IOException("Incorrect signature");
        }
        verifier_interface.verifyCertificatePath(certpath);
    }


    /**
     * Gets the signature algorithm.
     *
     * @return The algorithm identifier.
     * @throws IOException If anything unexpected happens...
     */
    public AsymSignatureAlgorithms getSignatureAlgorithm() throws IOException {
        for (AsymSignatureAlgorithms alg : AsymSignatureAlgorithms.values()) {
            if (alg.getDigestAlgorithm() == digest_algorithm) {
                return alg;
            }
        }
        throw new IOException("Unknown signature algorithm");
    }


    /**
     * Verifies a signed message and returns the signed data.
     *
     * @param message the signed data (PKCS#7 message blob).
     * @return the original data.
     * @throws IOException If anything unexpected happens...
     */
    public byte[] verifyMessage(byte message[]) throws IOException {
        try {
            new SignedData(DerDecoder.decode(message));
            verify();
            return this.message;
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }


    /**
     * Verifies a detached (not containing the actual data) signed message.
     *
     * @param message   the data to be verified.
     * @param signature the signature (PKCS#7 message blob).
     * @throws IOException If anything unexpected happens...
     */
    public void verifyDetachedMessage(byte message[], byte signature[]) throws IOException {
        try {
            new SignedData(DerDecoder.decode(signature), message);
            verify();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }


    /**
     * Creates a PKCS7Verifier using the given verifier object
     *
     * @param verifier {@link VerifierInterface VerifierInterface} containing the
     *                 certificates and method needed.
     */
    public PKCS7Verifier(VerifierInterface verifier) {
        this.verifier_interface = verifier;
    }

}
