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

public class Encoder {
    final static byte[] TRUE = {(byte) 0xFF};
    final static byte[] FALSE = {(byte) 0x00};
    final static byte[] EOC = {(byte) 0x00, (byte) 0x00};

    int maxPrimitiveStringLength = 1024;

    public void setMaxPrimitiveStringLength(int maxPrimitiveStringLength) {
        this.maxPrimitiveStringLength = maxPrimitiveStringLength;
    }

    public void write(byte[] b) {
        try {
            os.write(b);
            os.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            System.exit(0);
        }
    }

    public void write(byte[] b, int offset, int length) {
        try {
            if (length == -1) {
                length = b.length - offset;
            }
            os.write(b, offset, length);
            os.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            System.exit(0);
        }
    }

    public void write(int b) {
        try {
            os.write(b);
            os.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            System.exit(0);
        }
    }

    OutputStream os;

    public Encoder(OutputStream os) {
        this.os = os;
    }
}
