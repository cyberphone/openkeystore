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

import java.util.*;
import java.math.*;
import java.io.*;

import org.webpki.util.DebugFormatter;

public abstract class BaseASN1Object implements ASN1Constants {
    static byte[] bitMasks = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08,
                                        (byte) 0x10, (byte) 0x20, (byte) 0x40, (byte) 0x80};

    int tagClass;
    int tagEncoding;
    int tagNumber;

    /*
     * Create object.
     */
    BaseASN1Object(int tagClass, int tagNumber, boolean primitive) {
        this.tagClass = tagClass;
        this.tagNumber = tagNumber;
        this.tagEncoding = primitive ? PRIMITIVE : CONSTRUCTED;
    }

    /*
     * Create object.
     */
    BaseASN1Object(int tagNumber, boolean primitive) {
        this(UNIVERSAL, tagNumber, primitive);
    }

    // Holds a reference to the binary representation of this object,
    // if available
    byte[] blob;
    int blobOffset = -1;
    int encodedLength = -1;  // Will be set > 0 when the length is known.
    DerDecoder decoder;

    /*
     * Decode object.
     */
    BaseASN1Object(DerDecoder decoder) throws IOException {
        this.decoder = decoder;
//System.out.println(this.getClass().getName().substring(this.getClass().getName().lastIndexOf('.') + 1) + ": " + decoder.length);
        blob = decoder.source;
        blobOffset = decoder.startOffset;
        // Wil be true for all objects with PRIMITIVE encoding (and some constructed).
        if (decoder.endOffset > -1) {
            encodedLength = decoder.endOffset - decoder.startOffset;
        }

        tagClass = decoder.tagClass;
        tagEncoding = decoder.tagEncoding;
        tagNumber = decoder.tagNumber;
        if (tagClass == UNIVERSAL &&
                classToTagNumber.get(getClass()).intValue() != tagNumber) {
            throw new IOException("Internal error: types don't match.");
        }
    }

    /*
     * Decode substructure.
     * This should be the only way to decode substructures as it updates encodedLength!!!!
     */
    Vector<BaseASN1Object> readComponents(DerDecoder decoder) throws IOException {
        if (blob != decoder.source) {
            throw new IllegalArgumentException("Must use the same decoder!!!!");
        }

        Vector<BaseASN1Object> components = new Vector<BaseASN1Object>();

        int endOffset = decoder.endOffset;

        BaseASN1Object o;

        while ((o = decoder.readNext(endOffset)) != null) {
            components.addElement(o);
        }

        if (encodedLength == -1) {
            // encodedLength == -1 for _this_ object => 
            // this object is constructed and has indefinite length =>
            // at this stage, the last object read was an EOC which has known length => 
            // the below formula is correct (in fact it is correct in the other case too, 
            //   see temporary else-if branch below).
            encodedLength = decoder.endOffset - blobOffset;
        } else if (encodedLength != decoder.endOffset - blobOffset) {
            throw new RuntimeException("Corrupted ASN.1");
        }

        return components;
    }

    /**
     * Decode object, testing primitive/constructed.
     */
    BaseASN1Object(DerDecoder decoder, boolean primitive) throws IOException {
        this(decoder);
        if (isPrimitive() != primitive) {
            throw new IOException("Illegal encoding, expected " +
                    (primitive ? "primitive." : "constructed."));
        }
    }

    public abstract void encode(Encoder encoder) throws IOException;

    public void encode(OutputStream os) throws IOException {
        encode(new Encoder(os));
    }

    public byte[] encode() throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        encode(new Encoder(os));
        return os.toByteArray();
    }

    public ASN1OctetString encodedAsOctetString() throws IOException {
        return new ASN1OctetString(encode());
    }

    /*
     * Writes the already encoded value to the encoder, prepending the head.
     * The encoding of encodedValue should be primitive.
     */
    void encode(Encoder encoder, byte[] encodedValue) throws IOException {
        encodeHeader(encoder, encodedValue.length, true);
        encoder.write(encodedValue);
    }

    /*
     * Writes a constructed value to the encoder, prepending the head.
     */
    void encode(Encoder encoder, Vector<BaseASN1Object> components) throws IOException {
        encodeHeader(encoder, -1, false);
        for (int i = 0; i < components.size(); i++) {
            components.elementAt(i).encode(encoder);
        }
        encoder.write(Encoder.EOC);
    }

    /*
     * Write header of this object to the encoder.
     */
    void encodeHeader(Encoder encoder, int length) throws IOException {
        encodeHeader(encoder, length, tagEncoding == 0);
    }

    /*
     * Write header of this object to the encoder, forcing primitive/constructed flag.
     */
    void encodeHeader(Encoder encoder, int length, boolean primitive) throws IOException {
        if (tagNumber > 30) {
            throw new IOException("tagNumber > 30 not supported");
        }
        encoder.write(tagClass | (primitive ? DerDecoder.PRIMITIVE : DerDecoder.CONSTRUCTED) | tagNumber);
        if (length == -1) {
            encoder.write(0x80);
        } else if (length < 128) {
            encoder.write(length);
        } else {
            byte[] t = new BigInteger(Integer.toString(length)).toByteArray();
            //System.out.println(org.webpki.util.ArrayUtil.toHexString(t));
            // Remove leading zero if present
            if (t[0] == 0) {
                encoder.write((t.length - 1) | 0x80);
                encoder.write(t, 1, -1);
            } else {
                encoder.write(t.length | 0x80);
                encoder.write(t);
            }
        }
    }

    public byte[] encodeContent() throws IOException {
        // Uggly!!!!
        DerDecoder d = new DerDecoder(encode());
        d.readHeader();
        return d.content();
    }


    public BaseASN1Object get(int i) throws IOException {
        throw new IOException("Not composite");
    }

    public BaseASN1Object get(int[] path) throws IOException {
        BaseASN1Object o = this;
        for (int i = 0; i < path.length; i++) {
            o = o.get(path[i]);
        }
        return o;
    }

    boolean isPrimitive() {
        return tagEncoding == 0;
    }

    boolean isConstructed() {
        return !isPrimitive();
    }

    boolean isUniversal() {
        return tagClass == UNIVERSAL;
    }

    boolean isContext() {
        return tagClass == CONTEXT;
    }

    boolean isApplication() {
        return tagClass == APPLICATION;
    }

    boolean isPrivate() {
        return tagClass == PRIVATE;
    }

    String name() {
        return "<noname?>";
    }

    public void debug(Object o) {
        System.out.println(o);
    }

    /*
     * Perform deep comparison. Differences in encoding is ignored.
     */
    public abstract boolean deepCompare(BaseASN1Object o);

    public abstract boolean diff(BaseASN1Object o, StringBuilder s, String prefix);

    public String diff(BaseASN1Object o) {
        StringBuilder s = new StringBuilder();
        diff(o, s, "");
        return s.toString();
    }

    private static Hashtable<Class<?>, Integer> classToTagNumber = new Hashtable<Class<?>, Integer>();

    static {
        classToTagNumber.put(ASN1Boolean.class, new Integer(BOOLEAN));
        classToTagNumber.put(ASN1Integer.class, new Integer(INTEGER));
        classToTagNumber.put(ASN1BitString.class, new Integer(BITSTRING));
        classToTagNumber.put(ASN1OctetString.class, new Integer(OCTETSTRING));
        classToTagNumber.put(ASN1Null.class, new Integer(NULL));
        classToTagNumber.put(ASN1ObjectID.class, new Integer(OID));
        //classToTagNumber.put(ASN1ObjDescriptor.class, new Integer(OBJDESCRIPTOR));
        //classToTagNumber.put(ASN1External.class, new Integer(EXTERNAL));
        //classToTagNumber.put(ASN1Real.class, new Integer(REAL));
        classToTagNumber.put(ASN1Enumerated.class, new Integer(ENUMERATED));
        //classToTagNumber.put(ASN1Embedded_PDV.class, new Integer(EMBEDDED_PDV));
        classToTagNumber.put(ASN1UTF8String.class, new Integer(UTF8STRING));
        classToTagNumber.put(ASN1Sequence.class, new Integer(SEQUENCE));
        classToTagNumber.put(ASN1Set.class, new Integer(SET));
        classToTagNumber.put(ASN1NumericString.class, new Integer(NUMERICSTRING));
        classToTagNumber.put(ASN1PrintableString.class, new Integer(PRINTABLESTRING));
        classToTagNumber.put(ASN1T61String.class, new Integer(T61STRING));
        //classToTagNumber.put(ASN1VideotexString.class, new Integer(VIDEOTEXSTRING));
        classToTagNumber.put(ASN1IA5String.class, new Integer(IA5STRING));
        classToTagNumber.put(ASN1UTCTime.class, new Integer(UTCTIME));
        classToTagNumber.put(ASN1GeneralizedTime.class, new Integer(GENERALIZEDTIME));
        classToTagNumber.put(ASN1GraphicString.class, new Integer(GRAPHICSTRING));
        classToTagNumber.put(ASN1VisibleString.class, new Integer(VISIBLESTRING));
        classToTagNumber.put(ASN1GeneralString.class, new Integer(GENERALSTRING));
        //classToTagNumber.put(ASN1UniversalString.class, new Integer(UNIVERSALSTRING));
        classToTagNumber.put(ASN1BMPString.class, new Integer(BMPSTRING));
    }

    public int tagNumber() {
        return tagNumber;
    }

    /*
     * Comparison help method.
     */
    public boolean sameType(BaseASN1Object o) {
        return o.tagClass == tagClass && o.tagNumber == tagNumber;
    }

    public String toString(boolean extractfromoctetstrings, boolean bytenumbers) throws IOException {
        if (decoder == null) {
            DerDecoder dd = new DerDecoder(encode());
            return dd.readNext().toString(extractfromoctetstrings, bytenumbers);
        }
        decoder.extractfromoctetstrings = extractfromoctetstrings;
        decoder.bytenumbers = bytenumbers;
        StringBuilder s = new StringBuilder();
        toString(s, "");
        return s.toString();
    }

    String getByteNumber() {
        if (decoder == null || !decoder.bytenumbers) return "";
        int v = decoder.bytenumlistoffset + blobOffset;
        String s = Integer.toString(v);
        if (v < 10) s = "   " + s;
        else if (v < 100) s = "  " + s;
        else if (v < 1000) s = " " + s;
        return s + ": ";
    }

    String getByteNumberBlanks() {
        int j = getByteNumber().length();
        String off = "";
        while (--j >= 0) {
            off += " ";
        }
        return off;
    }

    void hexData(StringBuilder s, byte[] value) {
        if (value.length <= 16) {
            s.append(',');
            String hex = DebugFormatter.getHexString(value);
            int i = 0;
            while (i < hex.length()) {
                if (i % 2 == 0) s.append(' ');
                s.append(hex.charAt(i++));
            }
        } else {
            String hex = DebugFormatter.getHexDebugData(value);
            int i = 0;
            while (hex.length() > 0) {
                s.append("\n" + getByteNumberBlanks());
                if ((i = hex.indexOf('\n')) >= 0) {
                    s.append(hex.substring(0, i));
                    hex = hex.substring(i + 1);
                } else {
                    s.append(hex);
                    break;
                }
            }
        }
    }


    abstract void toString(StringBuilder s, String prefix);

    public String toString() {
        StringBuilder s = new StringBuilder();
        toString(s, "");
        return s.toString();
    }
}
