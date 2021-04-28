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
    
    private boolean readFlag;

    static final String INDENT = "  ";
    
    static final byte MT_UNSIGNED = (byte) 0x00;
    static final byte MT_NEGATIVE = (byte) 0x20;
    static final byte MT_BYTES    = (byte) 0x40;
    static final byte MT_STRING   = (byte) 0x60;
    static final byte MT_ARRAY    = (byte) 0x80;
    static final byte MT_MAP      = (byte) 0xa0;

    public abstract CBORTypes getType();

    public abstract byte[] encodeObject() throws IOException;
    
    abstract void internalToString(CBORObject initiator);
    
    byte[] getEncodedCodedValue(byte major, 
                                long value, 
                                boolean forceUnsigned,
                                boolean forcedNegative) {
        // 65-bit integer emulation...
        if (forcedNegative || (!forceUnsigned && value < 0)) {
            // Carsten B trickery :)
            value = ~value;
        }
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
            encoded = new byte[] {25, (byte) (value >> 8), (byte) value};
        } else {
            encoded = new byte[] {26, (byte) (value >> 24), (byte) (value >> 16), 
                                      (byte) (value >> 8),  (byte) value};
        } 
        encoded[0] |= major;
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
        return ((CBORInteger) this).value;
    }

    int getInt32() throws IOException {
        check(CBORTypes.INT);
        return (int)((CBORInteger) this).value;
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

    public static CBORObject decodeObject(byte[] cbor) {
        return null;
    }

    public void checkObjectForUnread() throws IOException {
        checkObjectForUnread(null);
    }

    private void checkObjectForUnread(String explanation) throws IOException {
        switch (getType()) {
        case STRING_MAP:
        case INTEGER_MAP:
            CBORMapBase cborMap = (CBORMapBase) this;
            for (CBORObject key : cborMap.keys.keySet()) {
                 cborMap.keys.get(key).checkObjectForUnread(key.toString());
            }
            break;
        case ARRAY:
            CBORArray cborArray = (CBORArray) this;
            for (CBORObject cborObject : cborArray.elements.toArray(new CBORArray[0])) {
                cborObject.checkObjectForUnread("Array element");
            }
            break;
        default:
            if (!readFlag) {
                throw new IOException("Type: " + getType() + " not read" +
                        (explanation == null ? "" : " (" + explanation + ")"));
            }
            break;
        }
    }
    
    @Override
    public boolean equals(Object obj) {
        try {
            System.out.println("EQ");
            return ArrayUtil.compare(((CBORObject) obj).encodeObject(), encodeObject());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    int indentationLevel;
    StringBuilder result;
    
    void indent() {
        for (int i = 0; i < indentationLevel; i++) {
            result.append(INDENT);
        }
    }

    @Override
    public String toString() {
        result = new StringBuilder();
        internalToString(this);
        return result.toString();
    }
}
