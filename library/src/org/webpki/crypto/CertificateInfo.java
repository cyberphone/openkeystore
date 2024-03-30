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

import java.util.GregorianCalendar;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;

import org.webpki.util.HexaDecimal;
import org.webpki.util.ISODateTime;

import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;
import org.webpki.asn1.ASN1BitString;
import org.webpki.asn1.ASN1Sequence;

public class CertificateInfo {

    private String issuerDn;

    private String serialNumber;

    private String subjectDn;

    private GregorianCalendar notValidBefore = new GregorianCalendar();

    private GregorianCalendar notValidAfter = new GregorianCalendar();

    private X509Certificate certificate;

    private boolean trusted;

    private boolean trustModeSet;


    public CertificateInfo(X509Certificate certificate, boolean trusted) {
        this.certificate = certificate;
        this.trusted = trusted;
        trustModeSet = true;
        issuerDn = CertificateUtil.convertRFC2253ToLegacy(
                certificate.getIssuerX500Principal().getName());
        serialNumber = certificate.getSerialNumber().toString();
        subjectDn = CertificateUtil.convertRFC2253ToLegacy(
                certificate.getSubjectX500Principal().getName());
        notValidBefore.setTime(certificate.getNotBefore());
        notValidAfter.setTime(certificate.getNotAfter());
    }


    public CertificateInfo(X509Certificate certificate) {
        this(certificate, true);
        trustModeSet = false;
    }


    private String getItem(String Item) {
        return Item == null ? "***UNKNOWN***" : Item;
    }

    private static String toDate(GregorianCalendar dateTime) {
        return ISODateTime.encode(dateTime, ISODateTime.UTC_NO_SUBSECONDS);
    }


    private void Conditional(StringBuilder sb, String prefix, String attribute) {
        if (attribute != null) {
            sb.append("      " + prefix + ": " + attribute + "\n");
        }
    }

    private String getFormattedSubject() {
        StringBuilder sb = new StringBuilder();
        if (subjectDn != null) {
            Conditional(sb, "Name", getSubjectCommonName());
            Conditional(sb, "SerialNumber", getSubjectSerialNumber());
            Conditional(sb, "Organization", getSubjectOrganization());
            Conditional(sb, "Organization Unit", getSubjectOrganizationUnit());
            Conditional(sb, "Country", getSubjectCountry());
            Conditional(sb, "e-mail", getSubjectEmail());
        }
        return sb.toString();
    }

    private String parseDN(String DNString, String tag) {
        if (DNString == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        boolean notfirst = false;
        int i = 0;
        while ((i = DNString.indexOf(tag, i)) >= 0) {
            boolean quot = false;
            boolean firstquoted = false;
            boolean lastquoted = false;
            int j = DNString.indexOf("=", i) + 1;
            int s = j;
            while (j < DNString.length()) {
                char ch = DNString.charAt(j);
                if (ch == ',' && !quot) {
                    break;
                }
                if (ch == '"') {
                    if (s == j) {
                        firstquoted = true;
                    } else {
                        lastquoted = true;
                    }
                    quot = !quot;
                } else {
                    lastquoted = false;
                }
                j++;
            }
            if (notfirst) {
                sb.append(", ");
            }
            notfirst = true;
            if (firstquoted && lastquoted) {
                s++;
                --j;
            }
            sb.append(DNString.substring(s, j));
            i = j;
        }
        return notfirst ? sb.toString() : null;
    }


    /*
     * Returns the subject's common name (CN).
     */
    public String getSubjectCommonName() {
        return parseDN(subjectDn, "CN=");
    }


    /*
     * Returns the subject's organization (O).
     */
    public String getSubjectOrganization() {
        return parseDN(subjectDn, "O=");
    }


    /*
     * Returns the subject's organizational unit (OU).
     */
    public String getSubjectOrganizationUnit() {
        return parseDN(subjectDn, "OU=");
    }


    /*
     * Returns the subject's e-mail address (E).
     */
    public String getSubjectEmail() {
        return parseDN(subjectDn, "E=");
    }


    /*
     * Returns the subject's country address (C).
     */
    public String getSubjectCountry() {
        return parseDN(subjectDn, "C=");
    }


    /*
     * Returns the subject's serial number (OID 2.5.4.5).
     */
    public String getSubjectSerialNumber() {
        return parseDN(subjectDn, "SerialNumber=");
    }


    /*
     * Returns the certificate hash.
     */
    public byte[] getCertificateHash() {
        return CertificateUtil.getCertificateSHA256(certificate);
    }


    /*
     * Returns the subject of this certificate
     */
    public String getSubject() {
        return getItem(subjectDn);
    }


    /*
     * Returns the issuer of this certificate
     */
    public String getIssuer() {
        return getItem(issuerDn);
    }


    /*
     * Returns the serial number of this certificate
     */
    public String getSerialNumber() {
        return getItem(serialNumber);
    }


    /*
     * Returns the start date of this certificate's validity period.
     */
    public GregorianCalendar getNotBeforeDate() {
        return notValidBefore;
    }


    /*
     * Returns the end date of this certificate's validity period.
     */
    public GregorianCalendar getNotAfterDate() {
        return notValidAfter;
    }


    /*
     * Checks certificate is currently valid.
     */
    public boolean isValid() {
        GregorianCalendar d = new GregorianCalendar();
        return d.after(notValidBefore) && d.before(notValidAfter);
    }


    public String[] getPolicyOIDs() {
        return CertificateUtil.getPolicyOIDs(certificate);
    }


    public String[] getAIAOCSPResponders() {
        return CertificateUtil.getAIAOCSPResponders(certificate);
    }


    public String[] getAIACAIssuers() {
        return CertificateUtil.getAIACAIssuers(certificate);
    }


    public String[] getExtendedKeyUsage() {
        return CertificateUtil.getExtendedKeyUsage(certificate);
    }


    public String[] getKeyUsages() {
        return CertificateUtil.getKeyUsages(certificate);
    }


    public String getBasicConstraints() {
        int i = certificate.getBasicConstraints();
        if (i == -1) {
            return "End-entity certificate";
        }
        return "CA certificate, path length constraint: " +
                (i == Integer.MAX_VALUE ? "none" : String.valueOf(i));
    }


    public String getPublicKeyAlgorithm() {
        return KeyAlgorithms.getKeyAlgorithm(
                certificate.getPublicKey()).getAlgorithmId(AlgorithmPreferences.SKS);
    }


    public String getSerialNumberInHex() {
        return HexaDecimal.encode(certificate.getSerialNumber().toByteArray());
    }


    public int getPublicKeySize() {
        return KeyAlgorithms.getKeyAlgorithm(certificate.getPublicKey()).getPublicKeySizeInBits();
    }


    public byte[] getCertificateBlob() {
        return CertificateUtil.getBlobFromCertificate(certificate);
    }


    public boolean isTrusted() {
        if (trustModeSet) {
            return trusted;
        }
        throw new CryptoException("Illegal call.  Trust is unknown");
    }


    public byte[] getPublicKeyData() {
        if (certificate.getPublicKey() instanceof RSAKey) {
            return DerDecoder.decode(
                    ((ASN1BitString) (
                            (ASN1Sequence) DerDecoder.decode(
                                    certificate.getPublicKey().getEncoded())).get(1))
                                        .value()).encode();
        }
        if (certificate.getPublicKey() instanceof ECKey) {
            return ParseUtil.bitstring(ParseUtil.sequence(DerDecoder.decode(
                    ((ECPublicKey) certificate.getPublicKey()).getEncoded()), 2).get(1));
        }
        return OkpSupport.public2RawKey(certificate.getPublicKey(),
                                        KeyAlgorithms.getKeyAlgorithm(certificate.getPublicKey()));
    }


    public String toString(boolean Verbose) {
        byte hash[] = getCertificateHash();
        return "  Subject DN: " + getSubject() + "\n" +
               "  Issuer DN: " + getIssuer() + "\n" +
               "  Serial number: " + getSerialNumber() + "\n" +
               (Verbose ? getFormattedSubject() : "") +
               "  Validity: " +
               toDate(notValidBefore) + " To " +
               toDate(notValidAfter) + (isValid() ? "" : " ***EXPIRED***") +
               (trusted ? "" : " ***UNKNOWN CA***") +
               "\n  SHA256 hash: " + (hash == null ? "BAD" : HexaDecimal.encode(hash));
    }


    public String toString() {
        return toString(false);
    }
}
  
