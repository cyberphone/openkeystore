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
package org.webpki.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import org.webpki.util.ArrayUtil;

public class KeyStoreReader {

    private KeyStoreReader() {} // No instantiation

    public static KeyStore loadKeyStore(byte[] buffer, String password) throws IOException {
        try {
            // JKS magic number + version (2)
            byte[] jks = {(byte) 0xfe, (byte) 0xed, (byte) 0xfe, (byte) 0xed, 0, 0, 0, 2};
            String type = "JKS";
            for (int i = 0; i < 8; i++) {
                if (buffer[i] != jks[i]) {
                    type = "PKCS12";
                    break;
                }
            }
            KeyStore ks = KeyStore.getInstance(type);
            ks.load(new ByteArrayInputStream(buffer), password.toCharArray());
            return ks;
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    public static KeyStore loadKeyStore(String keystoreFileName, String password) throws IOException {
        return loadKeyStore(ArrayUtil.readFile(keystoreFileName), password);
    }

    public static KeyStore loadKeyStore(InputStream inputStream, String password) throws IOException {
        return loadKeyStore(ArrayUtil.getByteArrayFromInputStream(inputStream), password);
    }
}
