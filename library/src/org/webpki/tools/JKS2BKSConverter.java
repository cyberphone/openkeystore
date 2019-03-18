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
package org.webpki.tools;

import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.util.Enumeration;

import java.security.KeyStore;
import java.security.Key;

import java.security.cert.Certificate;

import org.webpki.crypto.CustomCryptoProvider;


public class JKS2BKSConverter {

    public static void main(String argv[]) throws Exception {
        if (argv.length != 4) {
            System.out.println(JKS2BKSConverter.class.getName() + "  jksfile  bksfile/-same  storepass  keypass");
            System.exit(3);
        }
        CustomCryptoProvider.forcedLoad(true);
        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(new FileInputStream(argv[0]), argv[2].toCharArray());
        KeyStore bks = KeyStore.getInstance("BKS");
        bks.load(null, null);
        Enumeration<String> aliases = jks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (jks.isKeyEntry(alias)) {
                Certificate[] chain = jks.getCertificateChain(alias);
                Key key = jks.getKey(alias, argv[3].toCharArray());
                bks.setKeyEntry(alias, key, argv[3].toCharArray(), chain);
            } else if (jks.isCertificateEntry(alias)) {
                Certificate certificate = jks.getCertificate(alias);
                bks.setCertificateEntry(alias, certificate);
            } else {
                throw new Exception("Bad KS");
            }
        }
        bks.store(new FileOutputStream(argv[1].equals("-same") ? argv[0] : argv[1]), argv[2].toCharArray());
    }

}
