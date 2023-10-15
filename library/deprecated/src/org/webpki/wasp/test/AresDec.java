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
package org.webpki.wasp.test;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.wasp.AuthenticationResponseDecoder;


public class AresDec {

    private static void show() {
        System.out.println("AresDec inputfile\n");
        System.exit(3);
    }

    static AuthenticationResponseDecoder test(String in_file) throws Exception {
        byte[] data = IO.readFile(in_file);
        XMLSchemaCache schema_cache = new XMLSchemaCache();
        schema_cache.addWrapper(AuthenticationResponseDecoder.class);

        AuthenticationResponseDecoder ares = (AuthenticationResponseDecoder) schema_cache.parse(data);

        KeyStoreVerifier verifier = new KeyStoreVerifier(DemoKeyStore.getCAKeyStore());
        verifier.setTrustedRequired(false);

        ares.verifySignature(verifier);

        System.out.println("\nUSER AUTHENTICATION VERIFIED\n" + verifier.getSignerCertificate().toString());
        return ares;
    }


    public static void main(String args[]) throws Exception {
        if (args.length != 1) show();
        test(args[0]);
    }
}
