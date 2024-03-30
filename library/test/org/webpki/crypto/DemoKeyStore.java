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
package org.webpki.crypto;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyStore;


public class DemoKeyStore {

    public static String getSignerPassword() {
        return "testing";
    }

    private DemoKeyStore() {
    }

    public static KeyStore getMarionKeyStore() {
        return new DemoKeyStore().getKeyStore("marion.jks");
    }

    public static KeyStore getECDSAStore() {
        return new DemoKeyStore().getKeyStore("ecdsa.jks");
    }

    public static KeyStore getExampleDotComKeyStore() {
        return new DemoKeyStore().getKeyStore("example.jks");
    }

    public static KeyStore getMybankDotComKeyStore() {
        return new DemoKeyStore().getKeyStore("mybank.jks");
    }

    public static KeyStore getCAKeyStore() {
        return new DemoKeyStore().getKeyStore("root.jks");
    }

    public static KeyStore getSubCAKeyStore()  {
        return new DemoKeyStore().getKeyStore("subca.jks");
    }

    private KeyStore getKeyStore(String name) {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(getClass().getResourceAsStream(name), getSignerPassword().toCharArray());
            return ks;
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(e);
        }
    }

}
