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
package org.webpki.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ByteArrayOutputStream;

/**
 * Collection of file I/O functions.
 */
public class IO {
    private IO() {
    }  // No instantiation please

    public static byte[] readFile(File file) throws IOException {
        return getByteArrayFromInputStream(new FileInputStream(file));
    }

    public static byte[] readFile(String filename) throws IOException {
        return readFile(new File(filename));
    }

    public static void writeFile(File file, byte[] bytes) throws IOException {
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(bytes);
        fos.close();
    }

    public static void writeFile(String filename, byte[] bytes) throws IOException {
        writeFile(new File(filename), bytes);
    }

    public static void writeFile(String filename, String text) throws IOException {
        writeFile(new File(filename), UTF8.encode(text));
    }

    public static byte[] getByteArrayFromInputStream(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(10000);
        byte[] buffer = new byte[10000];
        int bytes;
        while ((bytes = is.read(buffer)) != -1) {
            baos.write(buffer, 0, bytes);
        }
        is.close();
        return baos.toByteArray();
    }
}
