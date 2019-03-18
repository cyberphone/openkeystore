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
package org.webpki.webauth;

import org.webpki.util.StringUtil;
import org.webpki.util.ArrayUtil;
import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.CertificateFilter;
import org.webpki.json.JSONDecoderCache;
import org.webpki.webauth.AuthenticationRequestDecoder;


public class AreqDec {

    private static void show() {
        System.out.println("AreqDec inputfile [options]\n" +
                "   -n   No object data output\n" +
                "   -d   Debug\n");
        System.exit(3);
    }

    static AuthenticationRequestDecoder test(String file, boolean outdata) throws Exception {

        byte[] data = ArrayUtil.readFile(file);

        JSONDecoderCache schema_cache = new JSONDecoderCache();
        schema_cache.addToCache(AuthenticationRequestDecoder.class);

        AuthenticationRequestDecoder areq = (AuthenticationRequestDecoder) schema_cache.parse(data);

        boolean signed = areq.isSigned();

        KeyStoreVerifier verifier = new KeyStoreVerifier(DemoKeyStore.getCAKeyStore());
        verifier.setTrustedRequired(false);

        if (signed) {
            areq.verifySignature(verifier);
        }

        StringBuilder s = new StringBuilder();

        for (CertificateFilter cf : areq.getCertificateFilters()) {
            SreqDec.printcf(cf, s);
        }

        s.append("\nID=" + areq.getID() + "\n");

        if (areq.getOptionalLanguageList() != null)
            s.append("\nLanguages=" + StringUtil.tokenList(areq.getOptionalLanguageList()) + "\n");

        if (signed) {
            s.append("\nSIGNATURE\n" + verifier.getSignerCertificate().toString() + "\nSIGNATURE");
        }

        if (outdata) {
            System.out.println(s.toString());
        }
        return areq;
    }

    public static void main(String args[]) throws Exception {
        if (args.length == 0) show();
        boolean outdata = true;
        boolean debug = false;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("-n")) outdata = false;
            else if (args[i].equals("-d")) debug = true;
            else show();
        }
        if (debug) System.out.println("Debug not available");  //Sorry...
        test(args[0], outdata);

    }

}
