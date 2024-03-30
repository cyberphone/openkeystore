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
package org.webpki.crypto;

import java.io.ByteArrayInputStream;

import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

import java.security.GeneralSecurityException;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

import javax.security.auth.x500.X500Principal;

import org.webpki.util.IO;
import org.webpki.util.UTF8;
import org.webpki.util.HexaDecimal;

import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.CompositeContextSpecific;
import org.webpki.asn1.ParseUtil;

import org.webpki.asn1.cert.SubjectAltNameTypes;

// Source configured for JDK.

/**
 * X509 certificate related operations.
 */ 
public class CertificateUtil {

    private CertificateUtil() {}  // No instantiation please

    public static final String AIA_CA_ISSUERS     = "1.3.6.1.5.5.7.48.2";
    public static final String AIA_OCSP_RESPONDER = "1.3.6.1.5.5.7.48.1";

    private static ASN1Sequence getExtension(X509Certificate certificate, 
                                             CertificateExtensions extension) {
        byte[] extensionBytes = certificate.getExtensionValue(extension.getOid());
        if (extensionBytes == null) {
            return null;
        }
        return ParseUtil.sequence(
                DerDecoder.decode(ParseUtil.octet(DerDecoder.decode(extensionBytes))));
    }

    public static X509Certificate[] getSortedPathFromPKCS7Bag(byte[] bag) {
        ArrayList<byte[]> certs = new ArrayList<>();

        ASN1Sequence outer = ParseUtil.sequence(DerDecoder.decode(bag));
        for (int i = 0; i < outer.size(); i++) {
            if (ParseUtil.isCompositeContext(outer.get(i), 0)) {
                ASN1Sequence inner = ParseUtil.sequence(ParseUtil.singleContext(outer.get(i), 0));
                for (int j = 0; j < inner.size(); j++) {
                    if (ParseUtil.isCompositeContext(inner.get(j), 0)) {
                        CompositeContextSpecific cert_entries =
                                ParseUtil.compositeContext(inner.get(j));
                        for (int k = 0; k < cert_entries.size(); k++) {
                            certs.add(cert_entries.get(k).encode());
                        }
                        return getSortedPathFromBlobs(certs);
                    }
                }
            }
        }
        throw new CryptoException("PKCS7 bag error");
    }

    public static String[] getKeyUsages(X509Certificate certificate) {
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage == null) {
            return null;
        }
        ArrayList<String> keyUsageSet = new ArrayList<>();
        int i = 0;
        for (KeyUsageBits kub : KeyUsageBits.values()) {
            if (i < keyUsage.length) {
                if (keyUsage[i++]) {
                    keyUsageSet.add(kub.getX509Name());
                }
            }
        }
        return keyUsageSet.toArray(new String[0]);
    }

    public static X509Certificate[] getSortedPath(X509Certificate[] certificatePath) {
        // Build/check path
        int n = 0;
        int[] idx = new int[certificatePath.length];
        int[] jidx = new int[certificatePath.length];
        boolean[] done = new boolean[certificatePath.length];
        for (int i = 0; i < certificatePath.length; i++) {
            X500Principal p = certificatePath[i].getIssuerX500Principal();
            idx[i] = -1;
            for (int j = 0; j < certificatePath.length; j++) {
                if (j == i || done[j]) continue;
                if (p.equals(certificatePath[j].getSubjectX500Principal()))
                { 
                    // Verify that J is certifying I
                    n++;
                    idx[i] = j;
                    jidx[j] = i;
                    done[j] = true;
                    if (verifyCertificate(certificatePath[i], certificatePath[j])) {
                        break;
                    }
                }
            }
        }
        if (n != (certificatePath.length - 1)) {
            throw new CryptoException(
                    "X509Certificate elements contain multiple or broken cert paths");
        }

        // Path OK, now sort it
        X509Certificate[] certpath = new X509Certificate[certificatePath.length];
        for (int i = 0; i < certificatePath.length; i++) {
            if (idx[i] < 0) // Must be the highest
            {
                certpath[n] = certificatePath[i];
                while (--n >= 0) {
                    certpath[n] = certificatePath[i = jidx[i]];
                }
                break;
            }
        }
        return certpath;
    }

    public static X509Certificate[] getSortedPathFromBlobs(List<byte[]> blobVector) {
        X509Certificate[] certificatePath = new X509Certificate[blobVector.size()];
        for (int i = 0; i < certificatePath.length; i++) {
            certificatePath[i] = getCertificateFromBlob(blobVector.get(i));
        }
        return getSortedPath(certificatePath);
    }

    public static String[] getPolicyOIDs(X509Certificate certificate) {
        ASN1Sequence outer = getExtension(certificate, 
                                          CertificateExtensions.CERTIFICATE_POLICIES);
        if (outer == null) {
            return null;
        }
        String[] oids = new String[outer.size()];
        for (int q = 0; q < outer.size(); q++) {
            oids[q] = ParseUtil.oid(ParseUtil.sequence(outer.get(q)).get(0)).oid();
        }
        return oids;
    }

    public static String[] getSubjectEmailAddresses(X509Certificate certificate) {
        HashSet<String> emailAddresses = new HashSet<>();

        Pattern pattern = 
                Pattern.compile("(^|,)(1\\.2\\.840\\.113549\\.1\\.9\\.1=#)([a-f0-9]+)(,.*|$)");
        Matcher matcher = pattern.matcher(certificate.getSubjectX500Principal().getName());
        if (matcher.find()) {
            emailAddresses.add(getHexASN1String(matcher.group(3)));
        }

        ASN1Sequence outer = getExtension(certificate, CertificateExtensions.SUBJECT_ALT_NAME);
        if (outer != null) {
            for (int q = 0; q < outer.size(); q++) {
                if (ParseUtil.isSimpleContext(outer.get(q), SubjectAltNameTypes.RFC822_NAME)) {
                    emailAddresses.add(UTF8.decode(ParseUtil.simpleContext(
                                outer.get(q), 
                                SubjectAltNameTypes.RFC822_NAME).value()));
                }
            }
        }
        return emailAddresses.isEmpty() ? null : emailAddresses.toArray(new String[0]);
    }

    private static String[] getAIAURIs(X509Certificate certificate, String subOid) {
        ASN1Sequence outer = getExtension(certificate, 
                                          CertificateExtensions.AUTHORITY_INFO_ACCESS);
        if (outer == null) {
            return null;
        }
        ArrayList<String> uris = new ArrayList<>();
        for (int q = 0; q < outer.size(); q++) {
            ASN1Sequence inner = ParseUtil.sequence(ParseUtil.sequence(outer.get(q)));
            if (inner.size() != 2) {
                throw new CryptoException("AIA extension size error");
            }
            if (ParseUtil.oid(inner.get(0)).oid().equals(subOid)) {
                if (ParseUtil.isSimpleContext(inner.get(1), 6)) {
                    String uri = UTF8.decode(
                            ParseUtil.simpleContext(inner.get(1), 6).value());
                    if (uri.startsWith("http")) {
                        // Sorry, we don't do LDAP [yet]
                        uris.add(uri);
                    }
                }
            }
        }
        return uris.isEmpty() ? null : uris.toArray(new String[0]);
    }

    public static String[] getAIAOCSPResponders(X509Certificate certificate){
        return getAIAURIs(certificate, AIA_OCSP_RESPONDER);
    }

    public static String[] getAIACAIssuers(X509Certificate certificate) {
        return getAIAURIs(certificate, AIA_CA_ISSUERS);
    }

    public static String[] getExtendedKeyUsage(X509Certificate certificate) {
        try {
            List<String> eku = certificate.getExtendedKeyUsage();
            if (eku == null) {
                return null;
            }
            return eku.toArray(new String[0]);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    private static String getHexASN1String(String asciiHex) {
        return ParseUtil.string(
                DerDecoder.decode(HexaDecimal.decode(asciiHex))).value();
    }

    private static String trycut(String olddn, 
                                 String pattern, 
                                 String replacement) {
        int i = olddn.indexOf(pattern);
        if (i >= 0) {
            int k = i + pattern.length();
            int j = k;
            while (j < olddn.length()) {
                char c = olddn.charAt(j);
                if (c == ',' || c == ' ') {
                    break;
                }
                j++;
            }
            try {
                return olddn.substring(0, i) + replacement +
                        getHexASN1String(olddn.substring(k, j)) +
                        olddn.substring(j);
            } catch (Exception e) {
            }
        }
        return olddn;
    }

    public static String convertRFC2253ToLegacy(String dn) {
        dn = trycut(dn, "1.2.840.113549.1.9.1=#", "E=");
        dn = trycut(dn, "2.5.4.5=#",              "SerialNumber=");
        dn = trycut(dn, "2.5.4.4=#",              "SurName=");
        dn = trycut(dn, "2.5.4.7=#",              "Locality=");
        dn = trycut(dn, "2.5.4.42=#",             "GivenName=");
        dn = trycut(dn, "2.5.4.41=#",             "Name=");
        StringBuilder s = new StringBuilder();
        boolean quoted = false;
        int i = 0;
        while (i < dn.length()) {
            char c = dn.charAt(i++);
            s.append(c);
            if (c == ',') {
                if (!quoted) {
                    s.append(' ');
                }
            } else if (c == '"') {
                quoted = !quoted;
            }
        }
        return s.toString();
    }

    public static String convertLegacyToRFC2253(String dn) {
        int i = dn.toLowerCase().indexOf(" e=");
        if (i < 0) i = dn.toLowerCase().indexOf(",e=");
        if (i > 0) {
            dn = dn.substring(0, ++i) + "EMAILADDRESS" + dn.substring(++i);
        }
        return new X500Principal(dn).getName(X500Principal.RFC2253);
    }

    public static byte[] getCertificateSHA1(X509Certificate certificate) {
        return HashAlgorithms.SHA1.digest(getBlobFromCertificate(certificate));
    }

    public static byte[] getCertificateSHA256(X509Certificate certificate) {
        return HashAlgorithms.SHA256.digest(getBlobFromCertificate(certificate));
    }
    
    public static boolean isTrustAnchor(X509Certificate certificate) {
        boolean trustAnchor = 
                certificate.getSubjectX500Principal().equals(
                        certificate.getIssuerX500Principal()) && 
                        certificate.getBasicConstraints() >= 0;
        return trustAnchor && verifyCertificate(certificate, certificate);
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("\nCheck path for:\n   {certificate-in-der-format}...");
        } else {
            try {
                ArrayList<byte[]> certPath = new ArrayList<>();
                for (String file : args) {
                    certPath.add(IO.readFile(file));
                }
                for (X509Certificate cert : getSortedPathFromBlobs(certPath)) {
                    System.out.println("\nCertificate:\n" + new CertificateInfo(cert));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    static boolean verifyCertificate(X509Certificate child, X509Certificate parent) {
        try {
            child.verify(parent.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static byte[] getBlobFromCertificate(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }
    
    public static X509Certificate[] checkCertificatePath(X509Certificate[] certificatePath) {
        X509Certificate signedCertificate = certificatePath[0];
        int i = 0;
        while (++i < certificatePath.length) {
            X509Certificate signerCertificate = certificatePath[i];
            String issuer = signedCertificate.getIssuerX500Principal().getName();
            String subject = signerCertificate.getSubjectX500Principal().getName();
            if (!issuer.equals(subject) ||
                !verifyCertificate(signedCertificate, signerCertificate)) {
                throw new CryptoException("Path issuer order error, '" + 
                                          issuer + "' versus '" + subject + "'");
            }
            signedCertificate = signerCertificate;
        }
        return certificatePath;
    }

    public static X509Certificate getCertificateFromBlob(byte[] encoded) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    public static X509Certificate[] makeCertificatePath(List<byte[]> certificateBlobs) {
        ArrayList<X509Certificate> certificates = new ArrayList<>();
        for (byte[] certificateBlob : certificateBlobs) {
            certificates.add(getCertificateFromBlob(certificateBlob));
        }
        return checkCertificatePath(certificates.toArray(new X509Certificate[0]));
    }
}
