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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ByteArrayOutputStream;

/**
 * Collection of file I/O functions.
 * <p>
 * Unlike java.io and java.nio classes, the methods declared here,
 * throw the <i>unchecked</i> {@link WrappedIOException}.
 * The intended use cases include client applications and test programs.
 * Server applications should probably stick to the standard java API.
 * </p>
 */
public class IO {
    /**
     * Exception wrapper.
     */
    public static class WrappedIOException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        WrappedIOException(IOException e) {
            super(e);
        }
    }
    
    private IO() {
    }  // No instantiation please

    public static byte[] readFile(String fileName) {
        try {
            return getByteArrayFromInputStream(new FileInputStream(fileName));
        } catch (IOException e) {
            throw new WrappedIOException(e);
        }
     }

    public static void writeFile(String fileName, byte[] bytes) {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(bytes);
        } catch (IOException e) {
            throw new WrappedIOException(e);
        }
    }

    public static void writeFile(String fileName, String text) {
        writeFile(fileName, UTF8.encode(text));
    }

    public static byte[] getByteArrayFromInputStream(InputStream inputStream) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(10000);
        byte[] buffer = new byte[10000];
        int bytes;
        try {
            while ((bytes = inputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, bytes);
            }
            inputStream.close();
        } catch (IOException e) {
            throw new WrappedIOException(e);
        }
        return baos.toByteArray();
    }
}
