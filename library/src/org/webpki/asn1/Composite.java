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
import java.util.*;

import org.webpki.util.ArrayUtil;

public abstract class Composite extends BaseASN1Object {
    Vector<BaseASN1Object> components;

    /**
     * Create object.
     */
    Composite(int tagClass, int tagNumber) {
        super(tagClass, tagNumber, false);
        components = new Vector<BaseASN1Object>();
    }

    /**
     * Create object.
     */
    @SuppressWarnings("unchecked")
    Composite(int tagClass, int tagNumber, Vector<BaseASN1Object> components) {
        this(tagClass, tagNumber);
        this.components = (Vector<BaseASN1Object>) components.clone();
    }

    /**
     * Create object.
     */
    Composite(int tagNumber, Vector<BaseASN1Object> components) {
        this(UNIVERSAL, tagNumber, components);
    }

    /**
     * Create object.
     */
    Composite(int tagClass, int tagNumber, BaseASN1Object[] components) {
        this(tagClass, tagNumber);
        this.components = new Vector<BaseASN1Object>();
        for (int i = 0; i < components.length; i++)
            this.components.addElement(components[i]);
    }

    /**
     * Create object.
     */
    Composite(int tagNumber, BaseASN1Object[] components) {
        this(UNIVERSAL, tagNumber, components);
    }

    /**
     * Create object.
     */
    Composite(int tagNumber) {
        this(UNIVERSAL, tagNumber);
    }

    Composite(DerDecoder decoder) throws IOException {
        super(decoder);

        if (isPrimitive()) {
            throw new IOException("Internal error: Primitive encoding of composite value.");
        }

        components = readComponents(decoder);
    }

    @SuppressWarnings("unchecked")
    public Vector<BaseASN1Object> components() {
        return (Vector<BaseASN1Object>) components.clone();
    }

    public int size() {
        return components.size();
    }

    public BaseASN1Object get(int i) {
        return components.elementAt(i);
    }

    public void encode(Encoder encoder) throws IOException {
        //*/encode(encoder, components);/*
        byte[] encodedValue = encode();
        encoder.write(encodedValue);//*/
    }

    public byte[] encode() throws IOException {
        byte[][] t = new byte[components.size()][];
        int length = 0;
        for (int i = 0; i < t.length; i++) {
            t[i] = (components.elementAt(i)).encode();
            length += t[i].length;
        }
        java.io.ByteArrayOutputStream os = new java.io.ByteArrayOutputStream();
        Encoder encoder = new Encoder(os);
        encodeHeader(encoder, length);
        for (int i = 0; i < t.length; i++) {
            encoder.write(t[i]);
        }
        return os.toByteArray();
    }

    public boolean deepCompare(BaseASN1Object o) {
        if (!sameType(o)) {
            return false;
        }
        return ASN1Util.deepCompare(((Composite) o).components, components);
    }

    public boolean diff(BaseASN1Object o, StringBuilder s, String prefix) {
        if (!sameType(o)) {
            s.append(prefix).append("<-------").append("    ");
            s.append(getClass().getName()).append(": ").append(tagClass).append(", ").append(tagNumber).append('\n');
            s.append(prefix).append("------->").append("    ");
            if (o instanceof Simple) {
                s.append(o).append('\n');
            }
            return true;
        }

        Composite c = (Composite) o;
        int n = Math.max(c.size(), size());
        boolean different = false;

        StringBuilder t = new StringBuilder();
        if (size() == c.size()) {
            t.append(prefix).append(getClass().getName()).append(": ").append(size()).append('\n');
        } else {
            t.append(prefix).append("<-------").append("    ");
            t.append(getClass().getName()).append(": ").append(size()).append('\n');
            t.append(prefix).append("------->").append("    ");
            t.append(c.getClass().getName()).append(": ").append(c.size()).append('\n');
        }
        for (int i = 0; i < n; i++) {
            if (i >= c.size()) {
                t.append(prefix).append("  <------- ").append(i).append("    ");
                get(i).toString(t, prefix + "  ");
                t.append('\n');
                different = true;
            } else if (i >= size()) {
                t.append(prefix).append("  -------> ").append(i).append("    ");
                c.get(i).toString(t, prefix + "  ");
                t.append('\n');
                different = true;
            } else {
                StringBuilder u = new StringBuilder();
                if (get(i).diff(c.get(i), u, prefix + "  ")) {
                    t.append(prefix).append("  <---").append(i).append("---> \n");
                    /*if(get(i) instanceof Simple)
                      t.append('\n');*/
                    t.append(u);//.append('\n');
                    different = true;
                }
            }
        }

        if (different) {
            s.append(t);//.append('\n');
            return true;
        }

        if (blob != null && o.blob != null) {
            int firstDiff = ArrayUtil.firstDiff(blob, blobOffset, o.blob, o.blobOffset, Math.min(encodedLength, o.encodedLength));
            // We have encoded values to compare.
            if (encodedLength != o.encodedLength) {
                // Encodings are of different length.
                s.append(prefix).append("<------- length ").append(encodedLength).append("    length ").append(o.encodedLength).append(" ------->").append('\n');
                s.append(prefix).append(firstDiff).append('\n');
                //s.append(prefix).append(blob[firstDiff]).append("     ").append(o.blob[firstDiff]).append('\n');
                s.append(prefix).append(ArrayUtil.toHexString(blob, blobOffset, Math.min(20, encodedLength))).append('\n');
                s.append(prefix).append(ArrayUtil.toHexString(o.blob, o.blobOffset, Math.min(20, o.encodedLength))).append('\n');
                toString(s, prefix);
                s.append('\n');
                /*s.append(prefix);
                o.toString(s, prefix);
                s.append('\n');//*/
            }
            for (int i = 0; i < size(); i++) {
                StringBuilder u = new StringBuilder();
                if (get(i).diff(c.get(i), u, prefix + "  ")) {
                    s.append(prefix).append("  <---").append(i).append("---> \n");
                    /*if(get(i) instanceof Simple)
                      t.append('\n');*/
                    s.append(u);//.append('\n');
                }
            }

            return encodedLength != o.encodedLength || firstDiff != -1;
        }

        return false;
    }

    void compositeString(StringBuilder s, String prefix) {
        s.append("\n  " + getByteNumberBlanks() + prefix + "{");
        for (int i = 0; i < components.size(); i++) {
            s.append("\n");
            components.elementAt(i).toString(s, prefix + "    ");
        }
        s.append("\n  " + getByteNumberBlanks() + prefix + "}");
    }


}
