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
package org.webpki.wasp.test;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.AuthorityInfoAccessCAIssuersCache;

import org.webpki.wasp.prof.xds.XDSProfileResponseDecoder;  // Mandatory profile

import org.webpki.wasp.SignatureResponseDecoder;
import org.webpki.wasp.SignatureProfileResponseDecoder;


public class SresDec {

    private static void show() {
        System.out.println("SresDec inputfile [-a]\n    -a  aia support\n");
        System.exit(3);
    }

    static SignatureResponseDecoder test(String in_file, boolean aia_support) throws Exception {
        byte[] data = ArrayUtil.readFile(in_file);
        XMLSchemaCache schema_cache = new XMLSchemaCache();
        schema_cache.addWrapper(SignatureResponseDecoder.class);
        schema_cache.addWrapper(XDSProfileResponseDecoder.class);

        SignatureResponseDecoder sres = (SignatureResponseDecoder) schema_cache.parse(data);

        SignatureProfileResponseDecoder prdec = sres.getSignatureProfileResponseDecoder();

        KeyStoreVerifier verifier = new KeyStoreVerifier(DemoKeyStore.getCAKeyStore());
        verifier.setTrustedRequired(false);
        if (aia_support) {
            verifier.setAuthorityInfoAccessCAIssuersHandler(new AuthorityInfoAccessCAIssuersCache());
        }

        prdec.verifySignature(verifier);

        System.out.println("\nUSER SIGNATURE VERIFIED\n" + verifier.getSignerCertificate().toString());
        return sres;
    }


    public static void main(String args[]) throws Exception {
        if (args.length < 1 || args.length > 2 || (args.length == 2 && !args[1].equals("-a")))
            show();
        test(args[0], args.length == 2);
    }

}
