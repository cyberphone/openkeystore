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

import java.io.IOException;

/**
 * Methods for testing datatypes (verifying ASN1 object structure).
 */
public class ParseUtil {
    static void bad(String msg) throws IOException {
        throw new IOException(msg);
    }

    public static ASN1Sequence sequence(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1Sequence)) {
            bad("Expected Sequence");
        }
        return (ASN1Sequence) o;
    }

    public static ASN1Sequence sequence(BaseASN1Object o, int size) throws IOException {
        ASN1Sequence seq = sequence(o);
        if (seq.size() != size) {
            bad("Expected length " + size + " Sequence");
        }
        return seq;
    }

    public static ASN1Sequence seqOIDValue(BaseASN1Object o) throws IOException {
        ASN1Sequence seq = sequence(o, 2);
        oid(seq.get(0));
        return seq;
    }

    public static BaseASN1Object seqOIDValue(BaseASN1Object o, String oid) throws IOException {
        ASN1Sequence seq = sequence(o, 2);
        oid(seq.get(0), oid);
        return seq.get(1);
    }

    public static ASN1ObjectID seqOIDNull(BaseASN1Object o) throws IOException {
        ASN1Sequence seq = sequence(o, 2);
        oid(seq.get(0));
        nul(seq.get(1));
        return (ASN1ObjectID) seq.get(0);
    }

    public static void seqOIDNull(BaseASN1Object o, String oid) throws IOException {
        ASN1Sequence seq = sequence(o, 2);
        oid(seq.get(0), oid);
        nul(seq.get(1));
    }

    public static void nul(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1Null)) {
            bad("Expected Null");
        }
    }

    public static Composite composite(BaseASN1Object o) throws IOException {
        if (!(o instanceof Composite)) {
            bad("Expected Composite type");
        }
        return (Composite) o;
    }

    public static Composite setOrSequence(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1Sequence) && !(o instanceof ASN1Set)) {
            bad("Expected Set or Sequence");
        }
        return (Composite) o;
    }

    public static ASN1Set set(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1Set)) {
            bad("Expected Set");
        }
        return (ASN1Set) o;
    }

    public static ASN1Set set(BaseASN1Object o, int size) throws IOException {
        ASN1Set set = set(o);
        if (set.size() != size) {
            bad("Expected length " + size + " Set");
        }
        return set;
    }

    public static boolean isContext(BaseASN1Object o, int tagNumber) {
        return isSimpleContext(o, tagNumber) || isCompositeContext(o, tagNumber);
    }

    public static boolean isSimpleContext(BaseASN1Object o, int tagNumber) {
        return o instanceof SimpleContextSpecific && o.tagNumber == tagNumber;
    }

    public static boolean isCompositeContext(BaseASN1Object o, int tagNumber) {
        return o instanceof CompositeContextSpecific && o.tagNumber == tagNumber;
    }

    public static CompositeContextSpecific compositeContext(BaseASN1Object o) throws IOException {
        if (!(o instanceof CompositeContextSpecific)) {
            bad("Expected CompositeContextSpecific");
        }
        return (CompositeContextSpecific) o;
    }

    public static SimpleContextSpecific simpleContext(BaseASN1Object o) throws IOException {
        if (!(o instanceof SimpleContextSpecific)) {
            bad("Expected SimpleContextSpecific");
        }
        return (SimpleContextSpecific) o;
    }

    public static SimpleContextSpecific simpleContext(BaseASN1Object o, int tagNumber)
            throws IOException {
        SimpleContextSpecific context = simpleContext(o);
        if (tagNumber != -1 && context.tagNumber() != tagNumber) {
            bad("Expected SimpleContextSpecific[" + tagNumber + "], found [" + context.tagNumber() + "].");
        }
        return context;
    }

    public static CompositeContextSpecific compositeContext(BaseASN1Object o, int tagNumber, int size)
            throws IOException {
        CompositeContextSpecific context = compositeContext(o);
        if (tagNumber != -1 && context.tagNumber() != tagNumber) {
            bad("Expected CompositeContextSpecific[" + tagNumber + "], found [" + context.tagNumber() + "].");
        }
        if (size != -1 && context.size() != size) {
            bad("Expected length " + size + " ContextSpecific");
        }
        return context;
    }

    public static CompositeContextSpecific compositeContext(BaseASN1Object o, int[] allowedTagNumbers)
            throws IOException {
        CompositeContextSpecific context = compositeContext(o);
        for (int i = 0; i < allowedTagNumbers.length; i++) {
            if (context.tagNumber() == allowedTagNumbers[i]) {
                return context;
            }
        }
        bad("Expected ContextSpecific[{set}], found " + context.tagNumber());
        return null;
    }

    public static SimpleContextSpecific simpleContext(BaseASN1Object o, int[] allowedTagNumbers)
            throws IOException {
        SimpleContextSpecific context = simpleContext(o);
        for (int i = 0; i < allowedTagNumbers.length; i++) {
            if (context.tagNumber() == allowedTagNumbers[i]) {
                return context;
            }
        }
        bad("Expected ContextSpecific[{set}], found " + context.tagNumber());
        return null;
    }

    public static BaseASN1Object singleContext(BaseASN1Object o, int tagNumber)
            throws IOException {
        return compositeContext(o, tagNumber, 1).get(0);
    }

    public static ASN1ObjectID oid(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1ObjectID)) {
            bad("Expected ObjectID");
        }
        return (ASN1ObjectID) o;
    }

    public static void oid(BaseASN1Object o, String allowedOID) throws IOException {
        ASN1ObjectID id = oid(o);
        if (!id.oid().equals(allowedOID)) {
            bad("Expected ObjectID " + allowedOID + ", found " + id.oid());
        }
    }

    public static ASN1ObjectID oid(BaseASN1Object o, String[] allowedOIDs) throws IOException {
        ASN1ObjectID id = oid(o);
        for (int i = 0; i < allowedOIDs.length; i++) {
            if (id.oid().equals(allowedOIDs[i])) {
                return id;
            }
        }
        bad("Expected ObjectID {set}, found " + id.oid());
        return null;
    }

    public static ASN1Integer integer(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1Integer)) {
            bad("Expected Integer");
        }
        return (ASN1Integer) o;
    }

    public static int integer(BaseASN1Object o, int allowedValue) throws IOException {
        int v = integer(o).intValue();
        if (v != allowedValue) {
            bad("Expected Integer " + allowedValue + ", found " + v);
        }
        return v;
    }

    public static int integer(BaseASN1Object o, int[] allowedValues) throws IOException {
        int v = integer(o).intValue();
        for (int i = 0; i < allowedValues.length; i++) {
            if (v == allowedValues[i]) {
                return v;
            }
        }
        bad("Expected Integer {set}, found " + v);
        return 0;
    }

    public static int enumerated(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1Enumerated)) {
            bad("Expected Enumerated");
        }
        return ((ASN1Enumerated) o).intValue();
    }

    public static int enumerated(BaseASN1Object o, int allowedValue) throws IOException {
        int v = enumerated(o);
        if (v != allowedValue) {
            bad("Expected Enumerated " + allowedValue + ", found " + v);
        }
        return v;
    }

    public static int enumerated(BaseASN1Object o, int[] allowedValues) throws IOException {
        int v = enumerated(o);
        for (int i = 0; i < allowedValues.length; i++) {
            if (v == allowedValues[i]) {
                return v;
            }
        }
        bad("Expected Enumerated {set}, found " + v);
        return 0;
    }

    public static byte[] octet(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1OctetString)) {
            bad("Expected OctetString");
        }
        return ((ASN1OctetString) o).value();
    }

    public static byte[] bitstring(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1BitString)) {
            bad("Expected BitString");
        }
        return ((ASN1BitString) o).value();
    }

    public static byte[] bitstring(BaseASN1Object o, int length) throws IOException {
        if (!(o instanceof ASN1BitString)) {
            bad("Expected BitString");
        }
        ASN1BitString bs = (ASN1BitString) o;
        byte[] data = bs.value();
        if (data.length * 8 - bs.unusedBits() > length) {
            throw new IOException("Bit String length error");
        }
        return data;
    }

    public static ASN1String string(BaseASN1Object o) throws IOException {
        if (!(o instanceof ASN1String)) {
            bad("Expected string type");
        }
        return (ASN1String) o;
    }
}
