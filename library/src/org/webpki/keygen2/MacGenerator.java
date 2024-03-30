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
package org.webpki.keygen2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.webpki.util.UTF8;

class MacGenerator {

    private ByteArrayOutputStream baos;

    MacGenerator() {
        baos = new ByteArrayOutputStream();
    }
    
    void writeBytes(byte[] data) {
        try {
            baos.write(data);
        } catch (IOException e) {
            throw new KeyGen2Exception(e);
        }
    }

    void addBlob(byte[] data) {
        addInt(data.length);
        writeBytes(data);
    }

    void addArray(byte[] data) {
        addShort(data.length);
        writeBytes(data);
    }

    void addString(String string) {
        addArray(UTF8.encode(string));
    }


    void addShort(int s) {
        baos.write((byte)(s >>> 8));
        baos.write((byte)(s));
    }
    
    void addInt(int i) {
        addShort(i >>> 16);
        addShort(i);
    }


    void addByte(byte b) {
        baos.write(b);
    }

    void addBool(boolean flag) {
        baos.write(flag ? (byte) 0x01 : (byte) 0x00);
    }

    byte[] getResult() {
        return baos.toByteArray();
    }
}
