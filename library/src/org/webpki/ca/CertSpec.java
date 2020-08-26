/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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

import java.util.ArrayList;
import java.util.Set;
import java.util.EnumSet;

import java.net.InetAddress;

import org.webpki.asn1.ASN1OctetString;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.ASN1IA5String;

import org.webpki.asn1.cert.RelativeDistinguishedName;
import org.webpki.asn1.cert.DistinguishedName;
import org.webpki.asn1.cert.SubjectAltNameTypes;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ExtendedKeyUsages;
import org.webpki.crypto.KeyUsageBits;


public class CertSpec {

    class NameValue {
        int name;
        BaseASN1Object value;

        NameValue(int name, BaseASN1Object value) {
            this.name = name;
            this.value = value;
        }
    }

    boolean endEntity;

    boolean caCert;

    boolean skiExtension;

    boolean akiExtension;

    Set<KeyUsageBits> keyUsageSet = EnumSet.noneOf(KeyUsageBits.class);

    Set<ExtendedKeyUsages> extendedKeyUsageSet = EnumSet.noneOf(ExtendedKeyUsages.class);

    ArrayList<String> certPolicyOids = new ArrayList<>();

    ArrayList<String[]> aiaLocators = new ArrayList<>();

    ArrayList<String> crlDistPoints = new ArrayList<>();

    private boolean hasGivenKeyUsage;

    private boolean defaultKeyUsage;

    private ArrayList<RelativeDistinguishedName> subject = new ArrayList<>();

    /**
     * Components for the <code>subjectAltName</code>.
     * The names used in this list should be the integer constants defined in
     * {@link org.webpki.asn1.cert.SubjectAltNameTypes SubjectAltNameTypes}.
     */
    ArrayList<NameValue> subjectAltName = new ArrayList<>();


    DistinguishedName getSubjectDistinguishedName() {
        return new DistinguishedName(subject.toArray(new RelativeDistinguishedName[0]));
    }


    private void setDefaultKeyUsage(KeyUsageBits[] kubits) {
        if (hasGivenKeyUsage) {
            return;
        }
        for (KeyUsageBits kubit : kubits) {
            setKeyUsageBit(kubit);
        }
        defaultKeyUsage = true;
    }


    public void setKeyUsageBit(KeyUsageBits kubit) {
        if (defaultKeyUsage) {
            defaultKeyUsage = false;
            keyUsageSet = EnumSet.noneOf(KeyUsageBits.class);
        }
        keyUsageSet.add(kubit);
        hasGivenKeyUsage = true;
    }


    public void setExtendedKeyUsage(ExtendedKeyUsages eku) {
        extendedKeyUsageSet.add(eku);
    }


    public void setEndEntityConstraint() {
        skiExtension = true;
        akiExtension = true;
        endEntity = true;
        setDefaultKeyUsage(new KeyUsageBits[]{KeyUsageBits.DIGITAL_SIGNATURE,
                                              KeyUsageBits.NON_REPUDIATION,
                                              KeyUsageBits.KEY_AGREEMENT,
                                              KeyUsageBits.DATA_ENCIPHERMENT,
                                              KeyUsageBits.KEY_ENCIPHERMENT});
    }


    public void setCACertificateConstraint() {
        skiExtension = true;
        akiExtension = true;
        caCert = true;
        setDefaultKeyUsage(new KeyUsageBits[]{KeyUsageBits.KEY_CERT_SIGN,
                                              KeyUsageBits.CRL_SIGN});
    }


    public void setSubjectKeyIdentifier() {
        skiExtension = true;
    }


    public void setAuthorityKeyIdentifier() {
        akiExtension = true;
    }


    public void addSubjectComponent(String name_or_oid, String value) throws IOException {
        subject.add(new RelativeDistinguishedName(name_or_oid, value));
    }


    private void bad(String err) throws IOException {
        throw new IOException("Subject DN error: " + err);
    }


    public void setSubject(String subject) throws IOException {
        ArrayList<String> dns = new ArrayList<>();
        boolean quote = false;
        StringBuilder s = new StringBuilder();
        int q = 0;
        while (q < subject.length()) {
            char c = subject.charAt(q++);
            if (c == ',' && !quote) {
                String attr = s.toString().trim();
                if (attr.length() > 0) {
                    dns.add(attr);
                    s = new StringBuilder();
                }
            } else if (c == '"') {
                quote = !quote;
            } else {
                s.append(c);
            }
        }
        if (quote) {
            throw new IOException("Bad quotes");
        }
        String attr = s.toString().trim();
        if (attr.length() > 0) {
            dns.add(attr);
        }
        String[] dn = dns.toArray(new String[0]);

        for (int i = dn.length; --i >= 0; )  // Reverse LDAP order
        {
            String nv = dn[i];
            int j = nv.indexOf('=');
            if (j <= 0) bad("= missing");
            String n = nv.substring(0, j).trim().toUpperCase();
            String v = nv.substring(j + 1).trim();
            if (n.length() == 0 || v.length() == 0) bad("zero length items");

            if (n.startsWith("OID")) {
                String t = n.substring(3);
                if (t.length() == 0) {
                    bad("malformed OID:\n\n  " + n);
                }

                while (t.length() > 0) {
                    if (t.charAt(0) != '.') {
                        bad("malformed OID:\n\n  " + n);
                    }
                    j = t.indexOf('.', 1);
                    if (j == -1) {
                        j = t.length();
                    }

                    try {
                        Integer.parseInt(t.substring(1, j));
                    } catch (NumberFormatException nfe) {
                        bad("malformed OID:\n\n  " + n);
                    }

                    t = t.substring(j);
                }
                n = n.substring(4);
            }
            addSubjectComponent(n, v);
        }
    }


    public void addSubjectAltNameElement(int name, BaseASN1Object value) {
        subjectAltName.add(new NameValue(name, value));
    }


    public void addEmailAddress(String address) {
        addSubjectAltNameElement(SubjectAltNameTypes.RFC822_NAME, new ASN1IA5String(address));
    }


    public void addDNSName(String name) {
        addSubjectAltNameElement(SubjectAltNameTypes.DNS_NAME, new ASN1IA5String(name));
    }


    public void addIPAddress(String ip_address) throws IOException {
        addSubjectAltNameElement(
                SubjectAltNameTypes.IP_ADDRESS, 
                new ASN1OctetString(InetAddress.getByName(ip_address).getAddress()));
    }


    public void addCertificatePolicyOID(String oid) {
        certPolicyOids.add(oid);
    }


    public void addOCSPResponderURI(String uri) {
        aiaLocators.add(new String[]{CertificateUtil.AIA_OCSP_RESPONDER, uri});
    }


    public void addCAIssuersURI(String uri) {
        aiaLocators.add(new String[]{CertificateUtil.AIA_CA_ISSUERS, uri});
    }


    public void addCRLDistributionPointURI(String uri) {
        crlDistPoints.add(uri);
    }

}
