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
package org.webpki.asn1.cert;

import java.io.IOException;

import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;

import java.util.Vector;
import java.util.Enumeration;
import java.util.Hashtable;

import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.ASN1Util;
import org.webpki.asn1.ParseUtil;

/**
 * X.509 DistinguishedName
 */
public class DistinguishedName {
    Vector<RelativeDistinguishedName> components = new Vector<RelativeDistinguishedName>();

    private ASN1Sequence asn1Representation;

    /*
     * Get the ASN.1 representation of this <code>DistinguishedName</code>.
     * @see org.webpki.asn1
     */
    public ASN1Sequence toASN1() {
        if (asn1Representation == null) {
            BaseASN1Object[] t = new BaseASN1Object[components.size()];

            Enumeration<RelativeDistinguishedName> e = components.elements();
            for (int i = 0; i < t.length; i++) {
                t[i] = e.nextElement().toASN1();
            }

            asn1Representation = new ASN1Sequence(t);
        }

        return asn1Representation;
    }

    /*
     * Hashvalue used to compare certificate issuers.
     * <p>Used when comparing two <code>DistinguishedName</code>s using the rules specified
     * in section 4.1.2.4 (top of p.21) of RFC2459 (X.509 v3).
     */
    long issuerHash;

    public int hashCode() {
        return (int) (issuerHash & 0x7FFFFFFF);
    }

    private void add(RelativeDistinguishedName rdn) {
        // Note: the hash could be more effective (in theory, that is).
        issuerHash += rdn.issuerHash;
        components.addElement(rdn);
    }

    /*
     * Construct an <code>DistinguishedName</code> from a BaseASN1Object ASN.1 structure.
     */
    public DistinguishedName(BaseASN1Object distinguishedName) throws IOException {
        asn1Representation = ParseUtil.sequence(distinguishedName);

        for (int i = 0; i < asn1Representation.size(); i++) {
            add(new RelativeDistinguishedName(asn1Representation.get(i)));
        }
    }

    /*
     * Construct an <code>DistinguishedName</code> from an array of RelativeDistinguishedNames.
     */
    public DistinguishedName(RelativeDistinguishedName[] relativeDistinguishedNames) {
        for (int i = 0; i < relativeDistinguishedNames.length; i++) {
            add(relativeDistinguishedNames[i]);
        }
    }

    /*
     * Create a <code>DistinguishedName</code> from a set of <code>OID</code>/value-pairs.
     */
    public DistinguishedName(Hashtable<String, String> nameOrOIDValuePairs) throws IOException {
        for (Enumeration<String> e = nameOrOIDValuePairs.keys(); e.hasMoreElements(); ) {
            String nameOrOID = e.nextElement(),
                    value = nameOrOIDValuePairs.get(nameOrOID);

            add(new RelativeDistinguishedName(nameOrOID, value));
        }
    }

    /*
     * Returns the DistinguishedName of a certificate subject.
     */
    public static DistinguishedName subjectDN(ASN1Sequence certificate)
            throws IOException, GeneralSecurityException {
        // First element, version, may be omitted (if "default"),
        // hence the index of subject may vary:
        ASN1Sequence seq = ParseUtil.sequence(certificate.get(0));
        return new DistinguishedName(seq.get(ParseUtil.isContext(seq.get(0), 0) ? 5 : 4));
    }

    /*
     * Returns the DistinguishedName of a certificate subject.
     */
    public static DistinguishedName subjectDN(X509Certificate certificate)
            throws IOException, GeneralSecurityException {
        return subjectDN(ASN1Util.x509Certificate(certificate));
    }

    /*
     * Returns the DistinguishedName of a certificate issuer.
     */
    public static DistinguishedName issuerDN(ASN1Sequence certificate)
            throws IOException, GeneralSecurityException {
        // First element, version, may be omitted (if "default"),
        // hence the index of issuer may vary:
        ASN1Sequence seq = ParseUtil.sequence(certificate.get(0));
        return new DistinguishedName(seq.get(ParseUtil.isContext(seq.get(0), 0) ? 3 : 2));
    }

    /*
     * Returns the DistinguishedName of a certificate issuer.
     */
    public static DistinguishedName issuerDN(X509Certificate certificate)
            throws IOException, GeneralSecurityException {
        return issuerDN(ASN1Util.x509Certificate(certificate));
    }

    /*
     * Tests if this DistinguishedName contains a specific RelativeDistinguishedName
     */
    public boolean hasComponent(RelativeDistinguishedName rdn) {
        return components.contains(rdn);
    }

    /*
     * Compare two DistinguishedNames in PKCS#7 Issuer type.
     */
    public boolean compare(DistinguishedName dn) {
        if (issuerHash != dn.issuerHash ||
                components.size() != dn.components.size()) {
            return false;
        }

        for (Enumeration<RelativeDistinguishedName> e = components.elements(); e.hasMoreElements(); ) {
            if (!dn.hasComponent(e.nextElement())) {
                return false;
            }
        }
        return true;
    }

    /*
     * Compare two <code>DistinguishedName</code>s in PKCS#7 Issuer type.
     */
    public boolean equals(Object o) {
        return o instanceof DistinguishedName &&
                compare((DistinguishedName) o);
    }

    public String toString() {
        StringBuilder s = new StringBuilder();
        int i = components.size() - 1;
        s.append(components.elementAt(i));  // Must have at least one element.

        for (i--; i >= 0; i--) {
            s.append(", ");
            components.elementAt(i).toString(s);
        }

        return s.toString();
    }
}
