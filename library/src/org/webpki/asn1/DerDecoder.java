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

import java.io.*;

import org.webpki.util.ArrayUtil;

public class DerDecoder implements ASN1Constants {
    private int offset = 0;
    /*private*/ byte[] source;
    boolean extractfromoctetstrings;

    boolean bytenumbers;

    int bytenumlistoffset;

    byte current() {
        return source[offset];
    }

    private byte next() {
        //System.out.println(Integer.toBinaryString((source[offset] & 0xFF) + 0x100).substring(1));
        return source[++offset];
    }

    int offset() {
        return offset;
    }

    boolean hasMore(int endOffset) {
        return !(source[offset] == 0 && source[offset + 1] == 0);
    }

    byte[] content() {
        if (offset + length > source.length) {
            throw new RuntimeException("Corrupted ASN.1");
        }
        byte[] r = new byte[length];
        System.arraycopy(source, offset, r, 0, length);
        offset += length;
        return r;
    }

    BaseASN1Object readNext(int endOffset) throws IOException {
        if (offset < source.length && (endOffset == -1 || offset < endOffset)) {
            return readNext();
        } else {
            return null;
        }
    }

    @SuppressWarnings("fallthrough")
    public BaseASN1Object readNext() throws IOException {
        if (!(offset < source.length)) {
            return null;
        }
        readHeader();
        switch (tagClass) {
            case CONTEXT:
                if (tagEncoding == ASN1Constants.PRIMITIVE) {
                    return new SimpleContextSpecific(this);
                } else {
                    return new CompositeContextSpecific(this);
                }
            case UNIVERSAL:
                switch (tagNumber) {
                    case EOC:
                        if (tagClass == 0 && tagEncoding == 0) {
                            //System.out.println("EOC");
                            return null;   //************ Should this be an object?
                        }/*else
                        switch(tagClass){
                          //case APPLICATION:
                          case CONTEXT:
                              return new ASN1ContextSpecific(this);
                          //case PRIVATE:
                          default:
                              throw new IOException("Kex? " + tagClass + ", " + tagEncoding + ", " + length);
                        }*/
                    case BOOLEAN:
                        return new ASN1Boolean(this);
                    case INTEGER:
                        return new ASN1Integer(this);
                    case BITSTRING:
                        return new ASN1BitString(this);
                    case OCTETSTRING:
                        return new ASN1OctetString(this);
                    case NULL:
                        return new ASN1Null(this);
                    case OID:
                        return new ASN1ObjectID(this);
                    //case OBJDESCRIPTOR:
                    //case EXTERNAL:
                    //case REAL:
                    case ENUMERATED:
                        return new ASN1Enumerated(this);
                    //case EMBEDDED_PDV:
                    case UTF8STRING:
                        return new ASN1UTF8String(this);
                    case SEQUENCE:
                        return new ASN1Sequence(this);
                    case SET:
                        return new ASN1Set(this);
                    case NUMERICSTRING:
                        return new ASN1NumericString(this);
                    case PRINTABLESTRING:
                        return new ASN1PrintableString(this);
                    case T61STRING:
                        return new ASN1T61String(this);
                    //case VIDEOTEXSTRING:
                    case IA5STRING:
                        return new ASN1IA5String(this);
                    case UTCTIME:
                        return new ASN1UTCTime(this);
                    case GENERALIZEDTIME:
                        return new ASN1GeneralizedTime(this);
                    case GRAPHICSTRING:
                        return new ASN1GraphicString(this);
                    case VISIBLESTRING:
                        return new ASN1VisibleString(this);
                    case GENERALSTRING:
                        return new ASN1GeneralString(this);
                    //case UNIVERSALSTRING:
                    case BMPSTRING:
                        return new ASN1BMPString(this);
                    default:
                        throw new IOException("********** Unknown/unsupported tag 0x" + ArrayUtil.toHexString(tagNumber, (char) 0) + " [" + length + "] **********");
                }
            default:
                throw new IOException("********** Only universal/context specific tags supported (0x" + Integer.toHexString(tagNumber) + " [" + length + "]) **********");
        }
    }

    public DerDecoder(byte[] source) {
        this.source = source;
    }

    public DerDecoder(byte[] source, int offset) {
        this.source = source;
        this.offset = offset;
    }

    public DerDecoder(String filename) throws IOException {
        File f = new File(filename);
        DataInputStream in = new DataInputStream(new FileInputStream(f));
        source = new byte[(int) f.length()];
        in.readFully(source);
        in.close();
    }

    public static BaseASN1Object decode(String filename)
            throws IOException, IOException {
        return new DerDecoder(filename).readNext();
    }

    public static BaseASN1Object decode(byte[] source) throws IOException {
        return new DerDecoder(source).readNext();
    }

    public static BaseASN1Object decode(byte[] source, int offset) throws IOException {
        return new DerDecoder(source, offset).readNext();
    }

    // Temp data
    int tagClass;
    int tagEncoding;
    int tagNumber;
    int startOffset;
    int length;
    int endOffset;

    void readHeader() {
        startOffset = offset;

        byte firstByte = current();

        tagNumber = 0;

        tagClass = firstByte & CLASS_MASK;
        tagEncoding = firstByte & FORM_MASK;

        if ((firstByte & TAG_MASK) != 0x1F) {
            // Single-byte tag
            tagNumber = (firstByte & TAG_MASK);
        } else {
            // Multiple-byte tag, last byte will have bit 8 = 0
            while ((next() & 0x80) != 0) {
                tagNumber = (tagNumber << 7) + (current() & 0x7F);
            }
        }

        length = 0;
        if ((next() & 0x80) == 0) {
            // Single byte length
            length = current() & 0x7F;
        } else {
            int l = current() & 0x7F;
            if (l == 0) {
                // Indefinite length
                length = -1;
            } else {
                // Multi-byte length
                //System.out.println("Multi-byte length " + l);
                for (int i = 0; i < l; i++) {
                    length = (length << 8) + (next() & 0xFF);
                }
            }
        }
//AR 2006-09-22++
        offset++;
//AR 2006-09-22--
        endOffset = (length == -1) ? -1 : offset + length;
        //System.out.println("Class: " + tagClass + ", encoding: " + tagEncoding + ", tag: 0x" + Integer.toHexString(tagNumber) + ", length: " + length);
    }

    public void debug(Object o) {
        System.out.println(o);
    }

    public void dumpSource() {
        for (int i = offset; i < offset + 40; i++) {
            System.out.print(Integer.toHexString(source[i] & 0xFF).toUpperCase() + " ");
        }
        System.out.println();
    }
}
