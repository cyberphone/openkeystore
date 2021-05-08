/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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

import java.math.BigInteger;

import java.util.GregorianCalendar;

import org.webpki.util.ArrayUtil;

/**
 * Base class for all CBOR objects.
 * 
 */
public abstract class CBORObject {
    
    CBORObject() {}
    
    // For checking if object was read
    boolean readFlag;

    // Major CBOR types
    static final byte MT_UNSIGNED      = (byte) 0x00;
    static final byte MT_NEGATIVE      = (byte) 0x20;
    static final byte MT_BYTE_STRING   = (byte) 0x40;
    static final byte MT_TEXT_STRING   = (byte) 0x60;
    static final byte MT_ARRAY         = (byte) 0x80;
    static final byte MT_MAP           = (byte) 0xa0;
    static final byte MT_DATE_TIME     = (byte) 0xc0;
    static final byte MT_BIG_UNSIGNED  = (byte) 0xc2;
    static final byte MT_BIG_SIGNED    = (byte) 0xc3;
    static final byte MT_FALSE         = (byte) 0xf4;
    static final byte MT_TRUE          = (byte) 0xf5;
    static final byte MT_NULL          = (byte) 0xf6;

    /**
     * Get core CBOR type.
     * 
     * @return The CBOR core type
     */
    public abstract CBORTypes getType();

    /**
     * Encode CBOR object.
     * 
     * @return Byte data
     * @throws IOException
     */
    public abstract byte[] encode() throws IOException;
    
    abstract void internalToString(PrettyPrinter prettyPrinter);
    
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

    void checkTypeAndMarkAsRead(CBORTypes requestedCborType) throws IOException {
        if (getType() != requestedCborType) {
            throw new IOException("Is type: " + getType() +
                    ", requested: " + requestedCborType);
        }
        readFlag = true;
    }
    
    public long getLong() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.INTEGER);
        return ((CBORInteger) this).getValueAsBigInteger().longValue();
    }

    public int getInt() throws IOException {
        return (int) getLong();
    }
    
    public boolean getBoolean() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.BOOLEAN);
        return ((CBORBoolean) this).value;
    }

    public boolean isNULL() throws IOException {
        checkTypeAndMarkAsRead(getType());
        return getType() == CBORTypes.NULL;
    }
    
    public BigInteger getBigInteger() throws IOException {
        if (getType() == CBORTypes.INTEGER) {
            checkTypeAndMarkAsRead(CBORTypes.INTEGER);
            return ((CBORInteger) this).getValueAsBigInteger();
        }
        checkTypeAndMarkAsRead(CBORTypes.BIG_INTEGER);
        return ((CBORBigInteger) this).value;
    }

    public String getTextString() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.TEXT_STRING);
        return ((CBORTextString) this).textString;
    }

    public GregorianCalendar getDateTime() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.DATE_TIME);
        return ((CBORDateTime) this).dateTime;
    }

    public byte[] getByteString() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.BYTE_STRING);
        return ((CBORByteString) this).byteString;
    }

    public CBORTextStringMap getTextStringMap() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.TEXT_STRING_MAP);
        return (CBORTextStringMap) this;
    }

    public CBORIntegerMap getIntegerMap() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.INTEGER_MAP);
        return (CBORIntegerMap) this;
    }

    public CBORArray getArray() throws IOException {
        checkTypeAndMarkAsRead(CBORTypes.ARRAY);
        return (CBORArray) this;
    }
    
    public CBORObject scan() throws IOException {
        checkTypeAndMarkAsRead(getType());
        return this;
    }
    
    static class CBORDecoder {

        static final int BUFFER_SIZE = 10000;
        private static final byte[] ZERO_BYTE = {0};
        private ByteArrayInputStream input;
         
        private CBORDecoder(byte[] encodedCborData) {
            input = new ByteArrayInputStream(encodedCborData);
        }
        
        private void bad() throws IOException {
            throw new IOException("Malformed CBOR, trying to read past EOF");
        }
        
        private int readByte() throws IOException {
            int i = input.read();
            if (i < 0) {
                bad();
            }
            return i;
        }
        
        private long checkLength(long length) throws IOException {
            if (length < 0) {
                throw new IOException("Length < 0");
            }
            return length;
        }

        private byte[] readBytes(long length) throws IOException {
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
        
        private CBORObject getObject() throws IOException {
            int first = readByte();

            // Begin with the types uniquely defined by the initial byte
            switch ((byte)first) {
            case MT_DATE_TIME:
                return new CBORDateTime(getObject().getTextString()); 
 
            case MT_BIG_SIGNED:
            case MT_BIG_UNSIGNED:
                byte[] byteArray = getObject().getByteString();
                if (byteArray.length == 0) {
                    byteArray = ZERO_BYTE;  // Zero length byte string => n == 0
                } else if (byteArray[0] == 0) {
                    throw new IOException("Non-deterministic encoding: leading zero byte");
                }
                BigInteger bigInteger = 
                    ((byte)first == MT_BIG_SIGNED) ?
                        new BigInteger(-1, byteArray).subtract(BigInteger.ONE)
                                                   :
                    new BigInteger(1, byteArray);
                if (CBORBigInteger.fitsAnInteger(bigInteger)) {
                    throw new IOException("Non-deterministic encoding: bignum fits integer");
                }
                return new CBORBigInteger(bigInteger);

            case MT_NULL:
                return new CBORNull();
                
            case MT_TRUE:
            case MT_FALSE:
                return new CBORBoolean((byte)first == MT_TRUE);
                
            default:
            }

            // Then decode the types blending length data in the initial byte as well
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
                    throw new IOException(
                        "Non-deterministic encoding: additional bytes form a zero value");
                }
            }
            switch (majorType) {
            case MT_UNSIGNED:
                return new CBORInteger(length, true);

            case MT_NEGATIVE:
                return new CBORInteger(length + 1, false);

            case MT_BYTE_STRING:
                return new CBORByteString(readBytes(checkLength(length)));

            case MT_TEXT_STRING:
                return new CBORTextString(new String(readBytes(checkLength(length)), "utf-8"));

            case MT_ARRAY:
                length = checkLength(length);
                CBORArray cborArray = new CBORArray();
                while (--length >= 0) {
                    cborArray.addElement(getObject());
                }
                return cborArray;

            case MT_MAP:
                length = checkLength(length);
                if (length == 0) {
                    // Empty map, special case
                    return new CBORTextStringMap();
                }
                CBORMapBase cborMapBase;
                CBORObject key1 = getObject();
                if (key1.getType() == CBORTypes.INTEGER) {
                    cborMapBase = new CBORIntegerMap();
                } else if (key1.getType() == CBORTypes.TEXT_STRING) {
                    cborMapBase = new CBORTextStringMap();
                } else {
                    throw new IOException(
                        "Only integer and text string map keys supported, found: " +
                         key1.getType());
                }
                cborMapBase.setObject(key1, getObject());
                while (--length > 0) {
                    CBORObject key = getObject();
                    if (key.getType() != key1.getType()) {
                        throw new IOException(
                            "Mixing key types in the same map is not supported: " +
                            key1.getType() + " versus " + key.getType());
                    }
                    cborMapBase.setObject(key, getObject());
                }
                return cborMapBase;

            default:
                throw new IOException("Unsupported tag: " + first);
            }
        }

        private void checkForUnexpectedInput() throws IOException {
            if (input.read() != -1) {
                throw new IOException("Unexpected data found after CBOR object");
            }
        }
    }

    /**
     * Decode CBOR data.
     * 
     * @param encodedCborData
     * @return CBOBObject
     * @throws IOException
     */
    public static CBORObject decode(byte[] encodedCborData) throws IOException {
        CBORDecoder cborDecoder = new CBORDecoder(encodedCborData);
        CBORObject cborObject = cborDecoder.getObject();
        cborDecoder.checkForUnexpectedInput();
        return cborObject;
    }

    /**
     * Check for unread CBOR data.
     * 
     * Check if all data from the current node and downwards have been read.
     * @throws IOException
     */
    public void checkObjectForUnread() throws IOException {
        checkObjectForUnread(null);
    }

    private void checkObjectForUnread(CBORObject holderObject) throws IOException {
        switch (getType()) {
        case TEXT_STRING_MAP:
        case INTEGER_MAP:
            CBORMapBase cborMap = (CBORMapBase) this;
            for (CBORObject key : cborMap.keys.keySet()) {
                 cborMap.keys.get(key).checkObjectForUnread(key);
            }
            break;
    
        case ARRAY:
            CBORArray cborArray = (CBORArray) this;
            for (CBORObject element : cborArray.getElements()) {
                element.checkObjectForUnread(cborArray);
            }
            break;
    
        default:
        }
        if (!readFlag) {
            throw new IOException((holderObject == null ? "Data" : 
                        holderObject instanceof CBORArray ?
                                "Array element" :
                                "Map key " + holderObject.toString()) +                    
                    " of type=" + getClass().getSimpleName() + 
                    " with value=" + toString() + " was never read");
        }
    }

    class PrettyPrinter {
 
        static final String INDENT = "  ";
        
        private int indentationLevel;
        private StringBuilder result;
               
        private PrettyPrinter() {
            result = new StringBuilder();
        }

        PrettyPrinter indent() {
            for (int i = 0; i < indentationLevel; i++) {
                result.append(INDENT);
            }
            return this;
        }
        
        PrettyPrinter beginStructure(String text) {
            appendText(text);
            indentationLevel++;
            return this;
        }

        PrettyPrinter endStructure(String text) {
            indentationLevel--;
            indent();
            appendText(text);
            return this;
        }

        PrettyPrinter appendText(String text) {
            result.append(text);
            return this;
        }
        
        String getTotalText() {
            return result.toString();
        }

        void insertComma() {
            result.insert(result.length() - 1, ',');
        }
    }

    @Override
    public boolean equals(Object object) {
        try {
            return ArrayUtil.compare(((CBORObject) object).encode(), encode());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        PrettyPrinter prettyPrinter = new PrettyPrinter();
        internalToString(prettyPrinter);
        return prettyPrinter.getTotalText();
    }
}
