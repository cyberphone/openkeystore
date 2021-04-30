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
package org.webpki.cbor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import org.webpki.util.ArrayUtil;

/**
 * Abstract class for holding CBOR objects.
 */
public abstract class CBORObject implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    CBORObject() {
        
    }
    
    // For checking if object was read
    private boolean readFlag;

    // Pretty-print support
    static final String INDENT = "  ";
    int indentationLevel;
    StringBuilder prettyPrint;
    
    // Major CBOR types
    static final byte MT_UNSIGNED      = (byte) 0x00;
    static final byte MT_NEGATIVE      = (byte) 0x20;
    static final byte MT_BYTES         = (byte) 0x40;
    static final byte MT_STRING        = (byte) 0x60;
    static final byte MT_ARRAY         = (byte) 0x80;
    static final byte MT_MAP           = (byte) 0xa0;
    static final byte MT_BIG_UNSIGNED  = (byte) 0xc2;
    static final byte MT_BIG_SIGNED    = (byte) 0xc3;
    static final byte MT_FALSE         = (byte) 0xf4;
    static final byte MT_TRUE          = (byte) 0xf5;
    static final byte MT_NULL          = (byte) 0xf6;

    public abstract CBORTypes getType();

    public abstract byte[] encode() throws IOException;
    
    abstract void internalToString(CBORObject initiator);
    
    byte[] getEncodedCore(byte majorType, long value) {
        byte[] encoded;
        if (value < 0 || value > 4294967295L) {
            encoded = new byte[9];
            encoded[0] = 27;
            for (int i = 8; i > 0; i--) {
                encoded[i] = (byte) value;
                value >>>= 8;
            } 
        } else if (value <= 23) {
            encoded = new byte[] {(byte) value};
        } else if (value <= 255) {
            encoded = new byte[] {24, (byte) value};
        } else if (value <= 65535) {
            encoded = new byte[] {25, (byte) (value >> 8),  (byte) value};
        } else {
            encoded = new byte[] {26, (byte) (value >> 24), (byte) (value >> 16), 
                                      (byte) (value >> 8),  (byte) value};
        } 
        encoded[0] |= majorType;
        return encoded;
    }

    void check(CBORTypes expectedCborType) throws IOException {
        if (getType() != expectedCborType) {
            throw new IOException("Is type: " + getType() +
                    ",  requested: " + expectedCborType);
        }
        readFlag = true;
    }

    long getInt64() throws IOException {
        check(CBORTypes.INT);
        return ((CBORInteger) this).getBigIntegerRepresentation().longValue();
    }

    int getInt32() throws IOException {
        return (int) getInt64();
    }
    
    boolean getBoolean() throws IOException {
        check(CBORTypes.BOOLEAN);
        return ((CBORBoolean) this).value;
    }
    
    public BigInteger getBigInteger() throws IOException {
        return CBORBigInteger.getValue(this);
    }

    public String getString() throws IOException {
        check(CBORTypes.STRING);
        return ((CBORString) this).string;
    }

    public byte[] getByteArray() throws IOException {
        check(CBORTypes.BYTE_ARRAY);
        return ((CBORByteArray) this).byteArray;
    }

    public CBORStringMap getCBORStringMap() throws IOException {
        check(CBORTypes.STRING_MAP);
        return (CBORStringMap) this;
    }

    public CBORIntegerMap getCBORIntegerMap() throws IOException {
        check(CBORTypes.INTEGER_MAP);
        return (CBORIntegerMap) this;
    }

    public CBORArray getCBORArray() throws IOException {
        check(CBORTypes.ARRAY);
        return (CBORArray) this;
    }
    
    static class CBORDecoder {

        static final int BUFFER_SIZE = 10000;
        ByteArrayInputStream input;
        
        CBORDecoder(byte[] encodedCborData) {
            input = new ByteArrayInputStream(encodedCborData);
        }
        
        void bad() throws IOException {
            throw new IOException("Malformed CBOR, trying to read past EOF");
        }
        
        int readByte() throws IOException {
            int i = input.read();
            if (i < 0) {
                bad();
            }
            return i;
        }
        
        long checkLength(long length) throws IOException {
            if (length < 0) {
                throw new IOException("Length < 0");
            }
            return length;
        }

        byte[] readBytes(long length) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(BUFFER_SIZE);
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytes = (int) (length > BUFFER_SIZE ? length % BUFFER_SIZE : length);
            while (length != 0) {
                if (input.read(buffer, 0, bytes) == -1) {
                    bad();
                }
                baos.write(buffer, 0, bytes);
                length -= bytes;
                bytes = BUFFER_SIZE;
            }
            return baos.toByteArray();
        }
        
        CBORObject getObject() throws IOException {
            int first = readByte();

            // Simple types first
            switch ((byte)first) {
            case MT_BIG_SIGNED:
            case MT_BIG_UNSIGNED:
                byte[] byteArray = getObject().getByteArray();
                if (byteArray[0] == 0) {
                    throw new IOException("Leading zero, improperly normalized");
                }
                if ((byte)first == MT_BIG_SIGNED) {
                    return new CBORBigInteger(
                            new BigInteger(-1, byteArray).subtract(BigInteger.ONE));
                }
                return new CBORBigInteger(new BigInteger(1, byteArray));
                
            case MT_NULL:
                return new CBORNull();
                
            case MT_TRUE:
            case MT_FALSE:
                return new CBORBoolean((byte)first == MT_TRUE);
                
            default:
            }

            // And then the more complex ones
            long length = first & 0x1f;
            byte majorType = (byte)(first & 0xe0);
            if (length > 0x1b) {
                throw new IOException("Not implemented: 0x1c-0x1f");
            }
            if (length > 0x17) {
                int q = 1 << (length - 0x18);
                length = 0;
                while (--q >= 0) {
                    length <<= 8;
                    length |= readByte();
                }
                if (length == 0) {
                    throw new IOException("Zero value found in extension bytes");
                }
            }
            switch (majorType) {
            case MT_UNSIGNED:
                return new CBORInteger(length, true);

            case MT_NEGATIVE:
                return new CBORInteger(length + 1, false);

            case MT_BYTES:
                return new CBORByteArray(readBytes(checkLength(length)));

            case MT_STRING:
                return new CBORString(new String(readBytes(checkLength(length)), "utf-8"));

            case MT_ARRAY:
                length = checkLength(length);
                CBORArray cborArray = new CBORArray();
                while (--length >= 0) {
                    cborArray.addObject(getObject());
                }
                return cborArray;

            case MT_MAP:
                length = checkLength(length);
                if (length == 0) {
                    // Empty map, special case
                    return new CBORStringMap();
                }
                CBORMapBase cborMapBase;
                CBORObject key1 = getObject();
                if (key1.getType() == CBORTypes.INT) {
                    cborMapBase = new CBORIntegerMap();
                } else if (key1.getType() == CBORTypes.STRING) {
                    cborMapBase = new CBORStringMap();
                } else {
                    throw new IOException("Only integer and string map keys supported " +
                                          key1.getType());
                }
                cborMapBase.setObject(key1, getObject());
                while (--length > 0) {
                    CBORObject key = getObject();
                    if (key.getType() != key1.getType()) {
                        throw new IOException(
                            "Mixing key types in the same map is not supported " +
                            key1.getType() + " " + key.getType());
                    }
                    cborMapBase.setObject(key, getObject());
                }
                return cborMapBase;

            default:
                throw new IOException("Unsupported tag: " + first);
            }
        }

        void checkForUnexpectedInput() throws IOException {
            if (input.read() != -1) {
                throw new IOException("Unexpected data found after CBOR object");
            }
        }
    }

    public static CBORObject decode(byte[] encodedCborData) throws IOException {
        CBORDecoder cborDecoder = new CBORDecoder(encodedCborData);
        CBORObject cborObject = cborDecoder.getObject();
        cborDecoder.checkForUnexpectedInput();
        return cborObject;
    }

    public void checkObjectForUnread() throws IOException {
        checkObjectForUnread(null);
    }

    private void checkObjectForUnread(CBORObject holderObject) throws IOException {
        switch (getType()) {
        case STRING_MAP:
        case INTEGER_MAP:
            CBORMapBase cborMap = (CBORMapBase) this;
            for (CBORObject key : cborMap.keys.keySet()) {
                 cborMap.keys.get(key).checkObjectForUnread(key);
            }
            break;

        case ARRAY:
            CBORArray cborArray = (CBORArray) this;
            for (CBORObject element : cborArray.elements.toArray(new CBORObject[0])) {
                element.checkObjectForUnread(cborArray);
            }
            break;

        default:
            if (!readFlag) {
                throw new IOException("Type " + getClass().getSimpleName() + 
                        " with data=" + toString() + " not read" +
                        (holderObject == null ? "" : 
                            holderObject instanceof CBORArray ?
                            " (featured in an array)" :
                            " (featured in key " + holderObject.toString() + ")"));
            }
            break;
        }
    }
    
    @Override
    public boolean equals(Object obj) {
        try {
            System.out.println("EQ");
            return ArrayUtil.compare(((CBORObject) obj).encode(), encode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    void indent() {
        for (int i = 0; i < indentationLevel; i++) {
            prettyPrint.append(INDENT);
        }
    }

    @Override
    public String toString() {
        prettyPrint = new StringBuilder();
        internalToString(this);
        return prettyPrint.toString();
    }
}
