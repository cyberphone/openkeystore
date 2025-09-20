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
package org.webpki.ca;

import java.math.BigInteger;

import java.util.ArrayList;
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
import org.webpki.crypto.KeyTypes;
import org.webpki.crypto.CertificateExtensions;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.CryptoException;


/*
    Certificate            ::=   SIGNED { SEQUENCE {
       version                 [0]   Version DEFAULT v1,
       serialNumber                  CertificateSerialNumber,
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

    private class Extensions {

        ArrayList<ASN1Sequence> extensions = new ArrayList<>();

        void add(CertificateExtensions extension, 
                 boolean critical, 
                 BaseASN1Object argument) {
            BaseASN1Object[] o = new BaseASN1Object[critical ? 3 : 2];
            o[0] = new ASN1ObjectID(extension.getOid());
            if (critical) {
                o[1] = new ASN1Boolean(true);
            }
            o[o.length - 1] = argument.encodedAsOctetString();
            extensions.add(new ASN1Sequence(o));
        }

        void add(CertificateExtensions extension, 
                 BaseASN1Object argument) {
            add(extension, false, argument);
        }

        boolean isEmpty() {
            return extensions.isEmpty();
        }

        ASN1Sequence getExtensionData() {
            return new ASN1Sequence(extensions.toArray(new ASN1Sequence[0]));
        }
    }


    private ASN1OctetString createKeyID(PublicKey publicKey) {
        return new ASN1OctetString(HashAlgorithms.SHA1.digest(publicKey.getEncoded()));
    }

    private ASN1Time getASN1Time(Date date) {
        GregorianCalendar gc = new GregorianCalendar();
        gc.setTime(date);
        if (gc.get(GregorianCalendar.YEAR) < 2050) {
            return new ASN1UTCTime(date);
        }
        return new ASN1GeneralizedTime(date);
    }
    
    private byte reverseBits(int value) {
        return (byte) Integer.reverse(value << 24);
    }


    public X509Certificate createCert(CertSpec certSpec,
                                      DistinguishedName issuerName,
                                      BigInteger serialNumber,
                                      Date startDate, Date endDate,
                                      AsymKeySignerInterface signer,
                                      PublicKey issuerPublicKey,
                                      PublicKey subjectPublicKey) {
        Extensions extensions = new Extensions();

        BaseASN1Object version = new CompositeContextSpecific(0, new ASN1Integer(2));

        DistinguishedName subjectName = certSpec.getSubjectDistinguishedName(); 

        BaseASN1Object validity = new ASN1Sequence(new BaseASN1Object[]{getASN1Time(startDate),
                                                                        getASN1Time(endDate)});

        AsymSignatureAlgorithms certSignAlg = signer.getAlgorithm();
        BaseASN1Object signatureAlgorithm = 
                new ASN1Sequence(certSignAlg.getKeyType() == KeyTypes.RSA ?
                        new BaseASN1Object[]{new ASN1ObjectID(certSignAlg.getOid()),
                                             new ASN1Null()}  // Relic from the RSA hey-days...
                                                 : 
                        new BaseASN1Object[]{new ASN1ObjectID(certSignAlg.getOid())});

        BaseASN1Object subjectPublicKeyInfo = DerDecoder.decode(subjectPublicKey.getEncoded());

        //==================================================//
        // Basic Constraints - EE
        //==================================================//
        if (certSpec.endEntity) {
            extensions.add(CertificateExtensions.BASIC_CONSTRAINTS, 
                           false, 
                           new ASN1Sequence(new BaseASN1Object[]{}));
        }

        //==================================================//
        // Basic Constraints - CA
        //==================================================//
        if (certSpec.caCert) {
            extensions.add(CertificateExtensions.BASIC_CONSTRAINTS, 
                           true, 
                           new ASN1Sequence(new ASN1Boolean(true)));
        }

        //==================================================//
        // Key Usage
        //==================================================//
        if (!certSpec.keyUsageSet.isEmpty()) {
            int i = 0;
            for (KeyUsageBits kubit : certSpec.keyUsageSet) {
                i |= 1 << kubit.ordinal();
            }
            byte[] keyUsage = new byte[i > 255 ? 2 : 1];
            keyUsage[0] = reverseBits(i);
            if (i > 255) {
                keyUsage[1] = reverseBits(i >> 8);
            }
            extensions.add(CertificateExtensions.KEY_USAGE, 
                           true, 
                           new ASN1BitString(keyUsage));
        }

        //==================================================//
        // Extended Key Usage
        //==================================================//
        if (!certSpec.extendedKeyUsageSet.isEmpty()) {
            int i = 0;
            BaseASN1Object[] ekus = new BaseASN1Object[certSpec.extendedKeyUsageSet.size()];
            for (ExtendedKeyUsages eku : 
                        certSpec.extendedKeyUsageSet.toArray(new ExtendedKeyUsages[0])) {
                ekus[i++] = new ASN1ObjectID(eku.getOID());
            }
            extensions.add(CertificateExtensions.EXTENDED_KEY_USAGE, 
                           false, 
                           new ASN1Sequence(ekus));
        }

        //==================================================//
        // Subject Key Identifier
        //==================================================//
        if (certSpec.skiExtension) {
            extensions.add(CertificateExtensions.SUBJECT_KEY_IDENTIFIER, 
                           createKeyID(subjectPublicKey));
        }

        //==================================================//
        // Authority Key Identifier
        //==================================================//
        if (certSpec.akiExtension) {
            extensions.add(CertificateExtensions.AUTHORITY_KEY_IDENTIFIER, 
                           new ASN1Sequence(
                                   new SimpleContextSpecific(0,
                                                             createKeyID(issuerPublicKey))));
        }

        //==================================================//
        // Subject Alt Name
        //==================================================//
        if (!certSpec.subjectAltName.isEmpty()) {
            int i = 0;
            BaseASN1Object[] san = new BaseASN1Object[certSpec.subjectAltName.size()];
            for (CertSpec.NameValue nameValue : certSpec.subjectAltName) {

                int type = nameValue.name;

                // We currently only handle simple IA5String types.
                if (type == SubjectAltNameTypes.RFC822_NAME ||
                    type == SubjectAltNameTypes.DNS_NAME ||
                    type == SubjectAltNameTypes.UNIFORM_RESOURCE_IDENTIFIER) {
                    if (!(nameValue.value instanceof ASN1IA5String)) {
                        throw new CryptoException(
                                "Wrong argument type to SubjectAltNames of type " + type);
                    }
                }
                // Or IP addresses.
                else if (type == SubjectAltNameTypes.IP_ADDRESS) {
                    if (!(nameValue.value instanceof ASN1OctetString)) {
                        throw new CryptoException(
                                "Wrong argument type to SubjectAltNames of type IP address");
                    }
                } else {
                    throw new CryptoException("SubjectAltNames of type " + type + " are not handled.");
                }
                san[i++] = new SimpleContextSpecific(type, nameValue.value);
            }
            extensions.add(CertificateExtensions.SUBJECT_ALT_NAME, 
                           new ASN1Sequence(san));
        }

        //==================================================//
        // Certificate Policies
        //==================================================//
        if (!certSpec.certPolicyOids.isEmpty()) {
            int i = 0;
            BaseASN1Object[] policies = new BaseASN1Object[certSpec.certPolicyOids.size()];
            for (String oid : certSpec.certPolicyOids) {
                policies[i++] = new ASN1Sequence(new ASN1ObjectID(oid));
            }
            extensions.add(CertificateExtensions.CERTIFICATE_POLICIES, 
                           new ASN1Sequence(policies));
        }

        //==================================================//
        // Authority Info Access
        //==================================================//
        if (!certSpec.aiaLocators.isEmpty()) {
            int i = 0;
            BaseASN1Object[] locators = new BaseASN1Object[certSpec.aiaLocators.size()];
            for (String[] loc_info : certSpec.aiaLocators) {
                locators[i++] = new ASN1Sequence(
                        new BaseASN1Object[]{new ASN1ObjectID(loc_info[0]),
                                new SimpleContextSpecific(6, new ASN1IA5String(loc_info[1]))}
                );
            }
            extensions.add(CertificateExtensions.AUTHORITY_INFO_ACCESS, 
                           new ASN1Sequence(locators));
        }

        //==================================================//
        // CRL Distribution Points
        //==================================================//
        if (!certSpec.crlDistPoints.isEmpty()) {
            int i = 0;
            BaseASN1Object[] cdps = new BaseASN1Object[certSpec.crlDistPoints.size()];
            for (String uri : certSpec.crlDistPoints) {
                cdps[i++] = new ASN1Sequence(
                        new CompositeContextSpecific(0,
                                new CompositeContextSpecific(0,
                                        new SimpleContextSpecific(6, new ASN1IA5String(uri))))
                );
            }
            extensions.add(CertificateExtensions.CRL_DISTRIBUTION_POINTS, 
                           new ASN1Sequence(cdps));
        }

        //==================================================//
        // Certificate Creation!
        //==================================================//
        BaseASN1Object[] inner = new BaseASN1Object[extensions.isEmpty() ? 7 : 8];
        inner[0] = version;
        inner[1] = new ASN1Integer(serialNumber);
        inner[2] = signatureAlgorithm;
        inner[3] = issuerName.toASN1();
        inner[4] = validity;
        inner[5] = subjectName.toASN1();
        inner[6] = subjectPublicKeyInfo;
        if (!extensions.isEmpty()) {
            inner[7] = new CompositeContextSpecific(3, extensions.getExtensionData());
        }

        BaseASN1Object tbsCertificate = new ASN1Sequence(inner);

        BaseASN1Object signature = 
                new ASN1BitString(signer.signData(tbsCertificate.encode()));

        byte[] certificate = new ASN1Sequence(new BaseASN1Object[]{tbsCertificate,
                                                                   signatureAlgorithm, 
                                                                   signature}).encode();
        
        return CertificateUtil.getCertificateFromBlob(certificate);
    }
}
