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

import java.util.Comparator;

/**
 * Abstract class for holding CBOR objects.
 */
public abstract class CBORObject implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    CBORObject() {
        
    }
    
    private boolean readFlag;

    CBORArray parent;
    
    static final String INDENT = "  ";
    
    public abstract CBORTypes getType();

    public abstract byte[] writeObject() throws IOException;
    
    abstract StringBuilder internalToString();
    
    StringBuilder parentDepthIndent() {
        StringBuilder stringBuilder = new StringBuilder();
        while (parent != null) {
            stringBuilder.append(INDENT);
            parent = parent.parent;
        }
        return stringBuilder;
    }

    private void check(CBORTypes expectedCborType) throws IOException {
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

    public String getString() throws IOException {
        check(CBORTypes.STRING);
        return ((CBORString) this).string;
    }

    public byte[] getByteArray() throws IOException {
        check(CBORTypes.BYTE_ARRAY);
        return ((CBORByteArray) this).byteArray;
    }

    public CBORStringMap getCBORStringMap() throws IOException {
        check(CBORTypes.MAP);
        return (CBORStringMap) this;
    }


    public CBORIntegerMap getCBORIntegerMap() {
        // TODO Auto-generated method stub
        return (CBORIntegerMap) this;
    }
    
    public CBORArray getCBORArray() throws IOException {
        check(CBORTypes.ARRAY);
        return (CBORArray) this;
    }

    public static CBORObject readObject(byte[] cbor) {
        return null;
    }

    public void checkObjectForUnread() throws IOException {
        checkObjectForUnread(null);
    }

    private void checkObjectForUnread(String explanation) throws IOException {
        switch (getType()) {
        case MAP:
            CBORMapBase cborMap = (CBORMapBase) this;
            for (CBORObject key : cborMap.keys.keySet()) {
                 cborMap.keys.get(key).checkObjectForUnread(CBORMapBase.keyText(key));
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
    public String toString() {
        return internalToString().append('\n').toString();
    }
}
