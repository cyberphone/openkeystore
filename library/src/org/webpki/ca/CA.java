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
package org.webpki.ca;

import java.io.IOException;

import java.math.BigInteger;

import java.util.Vector;
import java.util.Date;
import java.util.GregorianCalendar;

import java.security.cert.X509Certificate;

import java.security.PublicKey;

import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.ASN1Null;
import org.webpki.asn1.ASN1ObjectID;
import org.webpki.asn1.ASN1IA5String;
import org.webpki.asn1.ASN1OctetString;
import org.webpki.asn1.ASN1Boolean;
import org.webpki.asn1.ASN1Integer;
import org.webpki.asn1.ASN1BitString;
import org.webpki.asn1.ASN1Time;
import org.webpki.asn1.ASN1UTCTime;
import org.webpki.asn1.ASN1GeneralizedTime;
import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.SimpleContextSpecific;
import org.webpki.asn1.CompositeContextSpecific;
import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.cert.DistinguishedName;
import org.webpki.asn1.cert.SubjectAltNameTypes;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.ExtendedKeyUsages;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.CertificateExtensions;
import org.webpki.crypto.CertificateUtil;


/*
Certificate            ::=   SIGNED { SEQUENCE {
   version                 [0]   Version DEFAULT v1,
   serialNumber                 CertificateSerialNumber,
   signature                     AlgorithmIdentifier,
   issuer                        Name,
   validity                      Validity,
   subject                       Name,
   subjectPublicKeyInfo          SubjectPublicKeyInfo,
   issuerUniqueIdentifier  [1]   IMPLICIT UniqueIdentifier OPTIONAL,
                              ---if present, version shall be v2 or v3--
   subjectUniqueIdentifier [2]   IMPLICIT UniqueIdentifier OPTIONAL,
                              ---if present, version shall be v2 or v3--
   extensions              [3]   Extensions OPTIONAL
                              ---if present, version shall be v3--}  }
 */


public class CA {

    private static final byte[] reverse_bits = new byte[] {
        (byte) 0x00, (byte) 0x80, (byte) 0x40, (byte) 0xC0, (byte) 0x20, (byte) 0xA0, (byte) 0x60, (byte) 0xE0,
        (byte) 0x10, (byte) 0x90, (byte) 0x50, (byte) 0xD0, (byte) 0x30, (byte) 0xB0, (byte) 0x70, (byte) 0xF0,
        (byte) 0x08, (byte) 0x88, (byte) 0x48, (byte) 0xC8, (byte) 0x28, (byte) 0xA8, (byte) 0x68, (byte) 0xE8,
        (byte) 0x18, (byte) 0x98, (byte) 0x58, (byte) 0xD8, (byte) 0x38, (byte) 0xB8, (byte) 0x78, (byte) 0xF8,
        (byte) 0x04, (byte) 0x84, (byte) 0x44, (byte) 0xC4, (byte) 0x24, (byte) 0xA4, (byte) 0x64, (byte) 0xE4,
        (byte) 0x14, (byte) 0x94, (byte) 0x54, (byte) 0xD4, (byte) 0x34, (byte) 0xB4, (byte) 0x74, (byte) 0xF4,
        (byte) 0x0C, (byte) 0x8C, (byte) 0x4C, (byte) 0xCC, (byte) 0x2C, (byte) 0xAC, (byte) 0x6C, (byte) 0xEC,
        (byte) 0x1C, (byte) 0x9C, (byte) 0x5C, (byte) 0xDC, (byte) 0x3C, (byte) 0xBC, (byte) 0x7C, (byte) 0xFC,
        (byte) 0x02, (byte) 0x82, (byte) 0x42, (byte) 0xC2, (byte) 0x22, (byte) 0xA2, (byte) 0x62, (byte) 0xE2,
        (byte) 0x12, (byte) 0x92, (byte) 0x52, (byte) 0xD2, (byte) 0x32, (byte) 0xB2, (byte) 0x72, (byte) 0xF2,
        (byte) 0x0A, (byte) 0x8A, (byte) 0x4A, (byte) 0xCA, (byte) 0x2A, (byte) 0xAA, (byte) 0x6A, (byte) 0xEA,
        (byte) 0x1A, (byte) 0x9A, (byte) 0x5A, (byte) 0xDA, (byte) 0x3A, (byte) 0xBA, (byte) 0x7A, (byte) 0xFA,
        (byte) 0x06, (byte) 0x86, (byte) 0x46, (byte) 0xC6, (byte) 0x26, (byte) 0xA6, (byte) 0x66, (byte) 0xE6,
        (byte) 0x16, (byte) 0x96, (byte) 0x56, (byte) 0xD6, (byte) 0x36, (byte) 0xB6, (byte) 0x76, (byte) 0xF6,
        (byte) 0x0E, (byte) 0x8E, (byte) 0x4E, (byte) 0xCE, (byte) 0x2E, (byte) 0xAE, (byte) 0x6E, (byte) 0xEE,
        (byte) 0x1E, (byte) 0x9E, (byte) 0x5E, (byte) 0xDE, (byte) 0x3E, (byte) 0xBE, (byte) 0x7E, (byte) 0xFE,
        (byte) 0x01, (byte) 0x81, (byte) 0x41, (byte) 0xC1, (byte) 0x21, (byte) 0xA1, (byte) 0x61, (byte) 0xE1,
        (byte) 0x11, (byte) 0x91, (byte) 0x51, (byte) 0xD1, (byte) 0x31, (byte) 0xB1, (byte) 0x71, (byte) 0xF1,
        (byte) 0x09, (byte) 0x89, (byte) 0x49, (byte) 0xC9, (byte) 0x29, (byte) 0xA9, (byte) 0x69, (byte) 0xE9,
        (byte) 0x19, (byte) 0x99, (byte) 0x59, (byte) 0xD9, (byte) 0x39, (byte) 0xB9, (byte) 0x79, (byte) 0xF9,
        (byte) 0x05, (byte) 0x85, (byte) 0x45, (byte) 0xC5, (byte) 0x25, (byte) 0xA5, (byte) 0x65, (byte) 0xE5,
        (byte) 0x15, (byte) 0x95, (byte) 0x55, (byte) 0xD5, (byte) 0x35, (byte) 0xB5, (byte) 0x75, (byte) 0xF5,
        (byte) 0x0D, (byte) 0x8D, (byte) 0x4D, (byte) 0xCD, (byte) 0x2D, (byte) 0xAD, (byte) 0x6D, (byte) 0xED,
        (byte) 0x1D, (byte) 0x9D, (byte) 0x5D, (byte) 0xDD, (byte) 0x3D, (byte) 0xBD, (byte) 0x7D, (byte) 0xFD,
        (byte) 0x03, (byte) 0x83, (byte) 0x43, (byte) 0xC3, (byte) 0x23, (byte) 0xA3, (byte) 0x63, (byte) 0xE3,
        (byte) 0x13, (byte) 0x93, (byte) 0x53, (byte) 0xD3, (byte) 0x33, (byte) 0xB3, (byte) 0x73, (byte) 0xF3,
        (byte) 0x0B, (byte) 0x8B, (byte) 0x4B, (byte) 0xCB, (byte) 0x2B, (byte) 0xAB, (byte) 0x6B, (byte) 0xEB,
        (byte) 0x1B, (byte) 0x9B, (byte) 0x5B, (byte) 0xDB, (byte) 0x3B, (byte) 0xBB, (byte) 0x7B, (byte) 0xFB,
        (byte) 0x07, (byte) 0x87, (byte) 0x47, (byte) 0xC7, (byte) 0x27, (byte) 0xA7, (byte) 0x67, (byte) 0xE7,
        (byte) 0x17, (byte) 0x97, (byte) 0x57, (byte) 0xD7, (byte) 0x37, (byte) 0xB7, (byte) 0x77, (byte) 0xF7,
        (byte) 0x0F, (byte) 0x8F, (byte) 0x4F, (byte) 0xCF, (byte) 0x2F, (byte) 0xAF, (byte) 0x6F, (byte) 0xEF,
        (byte) 0x1F, (byte) 0x9F, (byte) 0x5F, (byte) 0xDF, (byte) 0x3F, (byte) 0xBF, (byte) 0x7F, (byte) 0xFF};


    private class Extensions {
        Vector<ASN1Sequence> extensions = new Vector<ASN1Sequence>();

        void add(CertificateExtensions extension, boolean critical, BaseASN1Object argument) throws IOException {
            BaseASN1Object[] o = new BaseASN1Object[critical ? 3 : 2];
            o[0] = new ASN1ObjectID(extension.getOid());
            if (critical) {
                o[1] = new ASN1Boolean(true);
            }
            o[o.length - 1] = argument.encodedAsOctetString();
            extensions.add(new ASN1Sequence(o));
        }

        void add(CertificateExtensions extension, BaseASN1Object argument) throws IOException {
            add(extension, false, argument);
        }

        boolean isEmpty() {
            return extensions.isEmpty();
        }

        ASN1Sequence getExtensionData() {
            return new ASN1Sequence(extensions.toArray(new ASN1Sequence[0]));
        }
    }


    private ASN1OctetString createKeyID(PublicKey pub_key) throws IOException {
        return new ASN1OctetString(HashAlgorithms.SHA1.digest(pub_key.getEncoded()));
    }

    private ASN1Time getASN1Time(Date date) throws IOException {
        GregorianCalendar gc = new GregorianCalendar();
        gc.setTime(date);
        if (gc.get(GregorianCalendar.YEAR) < 2050) {
            return new ASN1UTCTime(date);
        }
        return new ASN1GeneralizedTime(date);
    }


    public X509Certificate createCert(CertSpec cert_spec,
                                      DistinguishedName issuer_name,
                                      BigInteger serialNumber,
                                      Date start_date, Date end_date,
                                      AsymSignatureAlgorithms certalg,
                                      AsymKeySignerInterface signer,
                                      PublicKey subject_public_key) throws IOException {
        Extensions extensions = new Extensions();

        BaseASN1Object version = new CompositeContextSpecific(0, new ASN1Integer(2));

        DistinguishedName subject_name = cert_spec.getSubjectDistinguishedName();

        BaseASN1Object validity = new ASN1Sequence(new BaseASN1Object[]{getASN1Time(start_date),
                getASN1Time(end_date)});

        BaseASN1Object signatureAlgorithm =
                new ASN1Sequence(new BaseASN1Object[]{new ASN1ObjectID(certalg.getOid()),
                        new ASN1Null()});

        BaseASN1Object subjectPublicKeyInfo = DerDecoder.decode(subject_public_key.getEncoded());

        //////////////////////////////////////////////////////
        // Basic Constraints - EE
        //////////////////////////////////////////////////////
        if (cert_spec.end_entity) {
            extensions.add(CertificateExtensions.BASIC_CONSTRAINTS, false, new ASN1Sequence(new BaseASN1Object[]{}));
        }

        //////////////////////////////////////////////////////
        // Basic Constraints - CA
        //////////////////////////////////////////////////////
        if (cert_spec.ca_cert) {
            extensions.add(CertificateExtensions.BASIC_CONSTRAINTS, true, new ASN1Sequence(new ASN1Boolean(true)));
        }

        //////////////////////////////////////////////////////
        // Key Usage
        //////////////////////////////////////////////////////
        if (!cert_spec.key_usage_set.isEmpty()) {
            int i = 0;
            for (KeyUsageBits kubit : cert_spec.key_usage_set) {
                i |= 1 << kubit.ordinal();
            }
            byte[] keyUsage = new byte[i > 255 ? 2 : 1];
            keyUsage[0] = reverse_bits[i & 255];
            if (i > 255) {
                keyUsage[1] = reverse_bits[i >> 8];
            }
            extensions.add(CertificateExtensions.KEY_USAGE, true, new ASN1BitString(keyUsage));
        }

        //////////////////////////////////////////////////////
        // Extended Key Usage
        //////////////////////////////////////////////////////
        if (!cert_spec.extended_key_usage_set.isEmpty()) {
            int i = 0;
            BaseASN1Object[] ekus = new BaseASN1Object[cert_spec.extended_key_usage_set.size()];
            for (ExtendedKeyUsages eku : cert_spec.extended_key_usage_set.toArray(new ExtendedKeyUsages[0])) {
                ekus[i++] = new ASN1ObjectID(eku.getOID());
            }
            extensions.add(CertificateExtensions.EXTENDED_KEY_USAGE, false, new ASN1Sequence(ekus));
        }

        //////////////////////////////////////////////////////
        // Subject Key Identifier
        //////////////////////////////////////////////////////
        if (cert_spec.ski_extension) {
            extensions.add(CertificateExtensions.SUBJECT_KEY_IDENTIFIER, createKeyID(subject_public_key));
        }

        //////////////////////////////////////////////////////
        // Authority Key Identifier
        //////////////////////////////////////////////////////
        if (cert_spec.aki_extension) {
            extensions.add(CertificateExtensions.AUTHORITY_KEY_IDENTIFIER, new ASN1Sequence(new SimpleContextSpecific(0,
                    createKeyID(signer.getPublicKey()))));
        }

        //////////////////////////////////////////////////////
        // Subject Alt Name
        //////////////////////////////////////////////////////
        if (!cert_spec.subjectAltName.isEmpty()) {
            int i = 0;
            BaseASN1Object[] san = new BaseASN1Object[cert_spec.subjectAltName.size()];
            for (CertSpec.NameValue nameValue : cert_spec.subjectAltName) {

                int type = nameValue.name;

                // We currently only handle simple IA5String types.
                if (type == SubjectAltNameTypes.RFC822_NAME ||
                        type == SubjectAltNameTypes.DNS_NAME ||
                        type == SubjectAltNameTypes.UNIFORM_RESOURCE_IDENTIFIER) {
                    if (!(nameValue.value instanceof ASN1IA5String)) {
                        throw new IOException("Wrong argument type to SubjectAltNames of type " + type);
                    }
                }
                // Or IP addresses.
                else if (type == SubjectAltNameTypes.IP_ADDRESS) {
                    if (!(nameValue.value instanceof ASN1OctetString)) {
                        throw new IOException("Wrong argument type to SubjectAltNames of type IP address");
                    }
                } else {
                    throw new IOException("SubjectAltNames of type " + type + " are not handled.");
                }
                san[i++] = new SimpleContextSpecific(type, nameValue.value);
            }
            extensions.add(CertificateExtensions.SUBJECT_ALT_NAME, new ASN1Sequence(san));
        }

        //////////////////////////////////////////////////////
        // Certificate Policies
        //////////////////////////////////////////////////////
        if (!cert_spec.cert_policy_oids.isEmpty()) {
            int i = 0;
            BaseASN1Object[] policies = new BaseASN1Object[cert_spec.cert_policy_oids.size()];
            for (String oid : cert_spec.cert_policy_oids) {
                policies[i++] = new ASN1Sequence(new ASN1ObjectID(oid));
            }
            extensions.add(CertificateExtensions.CERTIFICATE_POLICIES, new ASN1Sequence(policies));
        }

        //////////////////////////////////////////////////////
        // Authority Info Access
        //////////////////////////////////////////////////////
        if (!cert_spec.aia_locators.isEmpty()) {
            int i = 0;
            BaseASN1Object[] locators = new BaseASN1Object[cert_spec.aia_locators.size()];
            for (String[] loc_info : cert_spec.aia_locators) {
                locators[i++] = new ASN1Sequence(
                        new BaseASN1Object[]{new ASN1ObjectID(loc_info[0]),
                                new SimpleContextSpecific(6, new ASN1IA5String(loc_info[1]))}
                );
            }
            extensions.add(CertificateExtensions.AUTHORITY_INFO_ACCESS, new ASN1Sequence(locators));
        }

        //////////////////////////////////////////////////////
        // CRL Distribution Points
        //////////////////////////////////////////////////////
        if (!cert_spec.crl_dist_points.isEmpty()) {
            int i = 0;
            BaseASN1Object[] cdps = new BaseASN1Object[cert_spec.crl_dist_points.size()];
            for (String uri : cert_spec.crl_dist_points) {
                cdps[i++] = new ASN1Sequence(
                        new CompositeContextSpecific(0,
                                new CompositeContextSpecific(0,
                                        new SimpleContextSpecific(6, new ASN1IA5String(uri))))
                );
            }
            extensions.add(CertificateExtensions.CRL_DISTRIBUTION_POINTS, new ASN1Sequence(cdps));
        }

        //////////////////////////////////////////////////////
        // Certificate Creation!
        //////////////////////////////////////////////////////
        BaseASN1Object[] inner = new BaseASN1Object[extensions.isEmpty() ? 7 : 8];
        inner[0] = version;
        inner[1] = new ASN1Integer(serialNumber);
        inner[2] = signatureAlgorithm;
        inner[3] = issuer_name.toASN1();
        inner[4] = validity;
        inner[5] = subject_name.toASN1();
        inner[6] = subjectPublicKeyInfo;
        if (!extensions.isEmpty()) {
            inner[7] = new CompositeContextSpecific(3, extensions.getExtensionData());
        }

        BaseASN1Object tbsCertificate = new ASN1Sequence(inner);

        BaseASN1Object signature = new ASN1BitString(signer.signData(tbsCertificate.encode(), certalg));

        byte[] certificate = new ASN1Sequence(new BaseASN1Object[]{tbsCertificate, signatureAlgorithm, signature}).encode();

        return CertificateUtil.getCertificateFromBlob(certificate);
    }

}
