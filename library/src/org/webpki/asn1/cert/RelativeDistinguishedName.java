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
import java.util.Hashtable;
import java.util.Enumeration;
import java.util.BitSet;

import org.webpki.asn1.ASN1String;
import org.webpki.asn1.ASN1IA5String;
import org.webpki.asn1.ASN1PrintableString;
import org.webpki.asn1.ASN1UTF8String;
import org.webpki.asn1.ASN1Set;
import org.webpki.asn1.ASN1ObjectID;
import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.ParseUtil;

import org.webpki.util.StringUtil;

/**
 * X.509 RelativeDistinguishedName (RDN), i.e.&nbsp;a subpart of an {@link DistinguishedName X.509 DistinguishedName}.
 */
public class RelativeDistinguishedName {
    /**
     * Mapping from OIDs to RDN component names.
     */
    private static Hashtable<String, String> oid2Name = new Hashtable<String, String>();
    /**
     * Mapping from RDN component names to OIDs.
     */
    private static Hashtable<String, String> name2OID = new Hashtable<String, String>();

    private static void addOIDName(String oid, String name) {
        oid2Name.put(oid, name);
        name2OID.put(name, oid);
    }

    static {
        // Initialize mappings
        addOIDName("2.5.4.3", "CN");
        addOIDName("2.5.4.4", "SN");
        addOIDName("2.5.4.5", "SERIALNUMBER");
        addOIDName("2.5.4.6", "C");
        addOIDName("2.5.4.7", "L");
        addOIDName("2.5.4.8", "S");  // a.k.a. "ST". M$ uses "S".
        addOIDName("2.5.4.10", "O");
        addOIDName("2.5.4.11", "OU");
        addOIDName("2.5.4.12", "T");
        addOIDName("2.5.4.42", "GN");
        addOIDName("1.2.840.113549.1.9.1", "EMAIL");
        addOIDName("1.2.840.113549.1.9.1", "EMAILADDRESS");
        addOIDName("1.2.840.113549.1.9.1", "E");
        addOIDName("0.9.2342.19200300.100.1.25", "DC");
    }

    /*
     * Get the OID corresponding to a RelativeDistinguishedName part name.
     */
    public static String name2OID(String name) {
        return name2OID.get(name.toUpperCase());
    }

    /*
     * Get the name corresponding to a RelativeDistinguishedName part OID.
    */
    public static String oid2Name(String oid) {
        return oid2Name.get(oid);
    }

    private Hashtable<String, ASN1String> components = new Hashtable<String, ASN1String>();

    private ASN1Set asn1Representation;

    /*
     * Get the ASN.1 representation of this RelativeDistinguishedName.
     */
    public ASN1Set toASN1() {
        if (asn1Representation == null) {
            BaseASN1Object[] t = new BaseASN1Object[components.size()];

            Enumeration<String> e = components.keys();
            for (int i = 0; i < t.length; i++) {
                String attribute = e.nextElement();

                t[i] = new ASN1Sequence(
                        new BaseASN1Object[]{
                                new ASN1ObjectID(attribute), components.get(attribute)
                        }
                );
            }

            asn1Representation = new ASN1Set(t);
        }

        return asn1Representation;
    }

    /*
     * Hashvalue used to compare certificate issuers.
     * Used when comparing two RelativeDistinguishedNames using 
     * the rules specified in section 4.1.2.4 (top of p.21) of RFC2459 (X.509 v3).
     */
    long issuerHash;

    public int hashCode() {
        return (int) (issuerHash & 0x7FFFFFFF);
    }

    private void add(String oid, ASN1String value) {
        issuerHash += (oid.hashCode() % 96797) *
                (rdnCanonical(value).hashCode() % 94771) *
                value.tagNumber(); // RESTORED: commented out due to corrupted nexus cert

        components.put(oid, value);
    }

    private void add(String nameOrOID, String value) throws IOException {
        if (nameOrOID.indexOf('.') < 0) {
            String t = name2OID(nameOrOID);
            if (t == null) {
                StringBuilder s = new StringBuilder();
                s.append("Unknown attribute '").append(nameOrOID).append("', select among the following:");
                Enumeration<String> e = name2OID.keys();
                while (e.hasMoreElements()) {
                    String key = e.nextElement();
                    s.append("\n  ").append(key).append("   [").append(name2OID.get(key)).append("]");
                }
                throw new IOException(s.toString());
            }
            nameOrOID = t;
        }

        // e-mail and dc as IA5String, all others as Printable or UTF-8 
        // (if contatining non-printable characters).
        add(nameOrOID, (nameOrOID.equals("1.2.840.113549.1.9.1") || nameOrOID.equals("0.9.2342.19200300.100.1.25")) ?
                (ASN1String) new ASN1IA5String(value) :
                ASN1PrintableString.isPrintableString(value) ?
                        (ASN1String) new ASN1PrintableString(value) :
                        (ASN1String) new ASN1UTF8String(value));
    }

    /*
     * Create a RelativeDistinguishedName from a set of OID value-pairs.
     */
    public RelativeDistinguishedName(Hashtable<String, String> nameOrOIDValuePairs) throws IOException {
        for (Enumeration<String> e = nameOrOIDValuePairs.keys(); e.hasMoreElements(); ) {
            String nameOrOID = e.nextElement(),
                    value = nameOrOIDValuePairs.get(nameOrOID);

            add(nameOrOID, value);
        }
    }

    /*
     * Create a RelativeDistinguishedName from a OID value-pair.
     */
    public RelativeDistinguishedName(String nameOrOID, String value) throws IOException {
        add(nameOrOID, value);
    }

    /*
     * Create a RelativeDistinguishedName from a BaseASN1Object ASN.1 structure.
     */
    public RelativeDistinguishedName(BaseASN1Object relativeDistinguishedName)
            throws IOException {
        asn1Representation = ParseUtil.set(relativeDistinguishedName);

        for (int i = 0; i < asn1Representation.size(); i++) {
            ASN1Sequence seq = ParseUtil.seqOIDValue(asn1Representation.get(i));
            add(ParseUtil.oid(seq.get(0)).oid(), ParseUtil.string(seq.get(1)));
        }
    }

    /*
     * The canonical value of an ASN1String when comparing RelativeDistinguishedNames
     */
    private String rdnCanonical(ASN1String s) {
        if (s instanceof ASN1PrintableString) {
            StringBuilder t = new StringBuilder(s.value().trim().toUpperCase());
            // Stupid algorithm, but this loop will never be executed.
            int i;
            while ((i = t.toString().indexOf("  ")) != -1)
                t.deleteCharAt(i);
            return t.toString();
        } else
            return s.value();
    }

    /*
     * Compare two values in PKCS#7 Issuer type.
     * Compares the two values using to the rules specified
     * in section 4.1.2.4 (top of p.21) of RFC2459 (X.509 v3).
     */
    public boolean compareValues(ASN1String v1, ASN1String v2) {
        return v1.sameType(v2) && // RESTORED: commented out due to corrupted nexus cert
                rdnCanonical(v1).equals(rdnCanonical(v2));
    }

    /*
     * Compare two <code>RelativeDistinguishedName</code>s in PKCS#7 Issuer type.
     * Compares the two values using to the rules specified
     * in section 4.1.2.4 (top of p.21) of RFC2459 (X.509 v3).
     */
    public boolean compare(RelativeDistinguishedName rdn) {
        if (issuerHash != rdn.issuerHash ||
                components.size() != rdn.components.size()) {
            return false;
        }
        for (Enumeration<String> keys = components.keys(); keys.hasMoreElements(); ) {
            String oid = keys.nextElement();
            if (!compareValues(components.get(oid), rdn.components.get(oid))) {
                return false;
            }
        }
        return true;
    }

    /*
     * Compare two <code>RelativeDistinguishedName</code>s in PKCS#7 Issuer type.
     * Compares the two values using to the rules specified
     * in section 4.1.2.4 (top of p.21) of RFC2459 (X.509 v3).
     */
    public boolean equals(Object o) {
        return o instanceof RelativeDistinguishedName &&
                compare((RelativeDistinguishedName) o);
    }

    // RFC1779: Characters that cause quoting.
    private final static BitSet quotedChars = StringUtil.charSet(",+=\"\n<>#;");

    public void toString(StringBuilder s) {
        boolean first = true;
        for (Enumeration<String> keys = components.keys(); keys.hasMoreElements(); ) {
            String oid = keys.nextElement(),
                    name = oid2Name.get(oid);
            if (!first) {
                s.append(" + ");
            }
            first = false;
            if (name != null) {
                s.append(name);
            } else {
                s.append("OID.").append(oid);
            }
            s.append("=");

            String value = components.get(oid).value();
            int i1 = 0, i2 = StringUtil.firstMember(value, quotedChars);

            if (i2 == -1) {
                // RFC1779: should still quote if there is leading, trailing or consequtive spaces.
                if (value.length() > 0 &&
                        (value.charAt(0) == ' ' || value.charAt(value.length() - 1) == ' ' ||
                                value.indexOf("  ") != -1)) {
                    s.append('\"').append(value).append('\"');
                } else {
                    s.append(value);
                }
            } else {
                s.append('\"');
                if (value.charAt(i2) != '\"' && value.indexOf('\"', i2) == -1) {
                    // No '\"' in value => straight copy
                    s.append(value);
                } else {
                    do {
                        s.append(value.substring(i1, i2));
                        s.append("\"\"");
                        i1 = i2 + 1;
                        i2 = value.indexOf('\"', i1);
                    }
                    while (i2 != -1);
                    s.append(value.substring(i1));
                }
                s.append('\"');
            }
        }
    }

    public String toString() {
        StringBuilder s = new StringBuilder();
        toString(s);
        return s.toString();
    }
}
