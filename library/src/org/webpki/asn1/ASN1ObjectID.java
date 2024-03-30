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
package org.webpki.asn1;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.math.*;
import java.util.*;

public final class ASN1ObjectID extends Simple {
    String id;

    public ASN1ObjectID(String id) {
        super(OID, true);
        this.id = id;
    }

    ASN1ObjectID(DerDecoder decoder) {
        super(decoder);
        byte[] content = decoder.content();
        int i = 0;
        while (i < content.length) {
            BigInteger subidentifier = BigInteger.ZERO;
            do {
                subidentifier = subidentifier.shiftLeft(7).add(new BigInteger(Integer.toString(content[i] & 0x7F)));
            }
            while ((content[i++] & 0x80) != 0);
            if (id == null) {
                // First subidentifier shall be split
                BigInteger[] t = subidentifier.divideAndRemainder(new BigInteger("40"));
                id = t[0] + "." + t[1];
            } else {
                id += "." + subidentifier;
            }
        }
    }

    public void encode(Encoder encoder) {
        ArrayList<BigInteger> v = new ArrayList<>();

        StringTokenizer st = new StringTokenizer(id, ".");
        while (st.hasMoreTokens()) {
            v.add(new BigInteger(st.nextToken()));
        }

        v.set(0, v.get(0).multiply(new BigInteger("40")).add(v.remove(1)));

        int length = 0;
        byte[][] oid_bytes = new byte[v.size()][];
        for (int i = 0; i < v.size(); i++) {
            BigInteger subID = v.get(i);
            byte[] t = new byte[(subID.bitLength() + 6) / 7];
            if (t.length == 0) {
                t = new byte[]{0};
            } else {
                for (int j = 0; j < t.length; j++) {
                    if (j < t.length - 1) {
                        t[j] = (byte) 0x80;
                    }
                    for (int k = 0; k < 7; k++) {
                        if (subID.testBit(7 * (t.length - j - 1) + k)) {
                            t[j] = (byte) (t[j] | bitMasks[k]);
                        }
                    }
                }
            }
            oid_bytes[i] = t;
            length += t.length;
        }

        encodeHeader(encoder, length, true);
        for (int i = 0; i < v.size(); i++) {
            encoder.write(oid_bytes[i]);
        }
    }

    public boolean deepCompare(BaseASN1Object o) {
        return sameType(o) && ((ASN1ObjectID) o).id.equals(id);
    }

    public String oid() {
        return id;
    }

    public Object objValue() {
        return oid();
    }

    public static String oidName(String oid) {
        String r;
        if (oidToName == null || (r = oidToName.get(oid)) == null) {
            return oid;
        } else {
            return r;
        }
    }

    public static String oid(String name) {
        String r;
        if (nameToOID == null || (r = nameToOID.get(name)) == null) {
            throw new ASN1Exception("Unknown OID name " + name + ".");//return oid;
        } else {
            return r;
        }
    }

    static Hashtable<String, String> oidToName, nameToOID;

    static {
        tryReadOIDNames(null);
    }

    public static void tryReadOIDNames(String filename) {
        Hashtable<String, String> on = new Hashtable<>(), no = new Hashtable<>();
        try {
            InputStream in = (filename == null) ?
                    new ASN1OIDDefinitions().getOIDStream() :
                    new FileInputStream(filename);
            BufferedReader r = new BufferedReader(new InputStreamReader(in));
            String s;
            while ((s = r.readLine()) != null) {
                if (s.startsWith("Description = ")) {
                    int i1 = s.indexOf("("), i2 = s.indexOf(")");
                    on.put(s.substring(i1 + 1, i2).replace(' ', '.'), 
                                       s.substring("Description = ".length(), i1 - 1));
                    no.put(s.substring("Description = ".length(), 
                                       i1 - 1), s.substring(i1 + 1, i2).replace(' ', '.'));
                }
            }
            r.close();
            oidToName = on;
            nameToOID = no;
        } catch (IOException e) {
            throw new ASN1Exception(e);
        }
    }

    void toString(StringBuilder s, String prefix) {
        String name = oidName(id);
        s.append(getByteNumber()).append(prefix).append("OBJECT IDENTIFIER ");
        if (!name.equals(id)) {
            s.append(oidName(id)).append(" ");
        }
        s.append("(").append(id).append(")");
    }

}
