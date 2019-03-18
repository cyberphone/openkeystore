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
package org.webpki.keygen2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

class MacGenerator {

    private ByteArrayOutputStream baos;

    MacGenerator() {
        baos = new ByteArrayOutputStream();
    }

    private byte[] short2bytes(int s) {
        return new byte[]{(byte) (s >>> 8), (byte) s};
    }

    private byte[] int2bytes(int i) {
        return new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
    }

    void addBlob(byte[] data) throws IOException {
        baos.write(int2bytes(data.length));
        baos.write(data);
    }

    void addArray(byte[] data) throws IOException {
        baos.write(short2bytes(data.length));
        baos.write(data);
    }

    void addString(String string) throws IOException {
        addArray(string.getBytes("UTF-8"));
    }

    void addInt(int i) throws IOException {
        baos.write(int2bytes(i));
    }

    void addShort(int s) throws IOException {
        baos.write(short2bytes(s));
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
