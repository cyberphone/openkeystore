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

import java.io.IOException;
import java.io.FileInputStream;

import java.net.URL;
import java.util.Date;
import java.util.GregorianCalendar;
import java.security.KeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLCookie;
import org.webpki.xml.XMLSchemaCache;
import org.webpki.xmldsig.test.xmlobject;

import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.SignerInterface;

import org.webpki.wasp.AuthenticationRequestDecoder;
import org.webpki.wasp.AuthenticationResponseEncoder;
import org.webpki.wasp.ClientPlatformFeature;


public class AresEnc {


    static void test(String in_file, String out_file, SignerInterface signer, boolean localfixed,
                     boolean respprefix) throws Exception {

// The following is equivalent to the receival of of a AuthenticationRequest
        AuthenticationRequestDecoder authdec = AreqDec.test(in_file, false);
        System.out.println("SIGALG=" + authdec.getAuthenticationProfiles()[0].getSignatureAlgorithm());

// Now the user is supposed to look on the auth request displayed on his/her screen

// Now the user have accepted and also been prompted for PIN-code.  Let's rock!
// The following creates a matching AuthenticationResponse

        AuthenticationResponseEncoder authenc = new AuthenticationResponseEncoder();

        if (authdec.getRequestedClientPlatformFeatures().length > 0) {
            xmlobject o = new xmlobject();
            o.id = "id.1234";
            o.value = "Some text";
            o.forcedDOMRewrite();
            authenc.addClientPlatformFeature(new ClientPlatformFeature(authdec.getRequestedClientPlatformFeatures()[0],
                    new XMLCookie(o)));
        }

        if (respprefix) {
            authenc.setPrefix("RESP");
        }

        authenc.createSignedResponse(signer,
                authdec,
                (new URL(new URL(authdec.getSubmitUrl()), "authreq")).toString(),
                localfixed ?
                        new GregorianCalendar(2006, 0, 1, 10, 0, 0).getTime()
                        :
                        new Date(),
                null);
// Which is to be HTTP POSTed but here just put on a file

        byte[] data = authenc.writeXML();
        ArrayUtil.writeFile(out_file, data);
        XMLSchemaCache sc = new XMLSchemaCache();
        sc.addWrapper(authenc);
        sc.validate(data);
    }

    private static void show() {
        System.out.println("AresEnc in_file out_file [options]\n\n" +
                " in_file:  Must contain a complete authentication request\n" +
                " out_file: Result will be written here\n" +
                "\n options:\n" +
                "   -b                 Built-in demo key-store, requires NO passwords\n" +
                "   -t                 Keep local time constant\n" +
                "   -k key_file        Java JKS type of keystore\n" +
                "   -w storepassword   MUST for 'key_file'\n" +
                "   -u signpassword    MUST for 'key_file'\n" +
                "   -a keyalias        Signature key alias\n");
        System.exit(3);
    }

    private static String argtest(String args[], int index) throws IOException {
        String arg = args[index];
        if (arg.startsWith("-"))
            throw new IOException("Argument \"" + arg + "\" on index[" + index + "] cannot start with \"-\"");
        return arg;
    }

    public static void main(String args[]) throws Exception {
        if (args.length < 3) show();
        String keyAlias = null;
        String storepassword = null;
        String signpassword = null;
        boolean localfixed = false;
        String key_file = null;
        KeyStore ks = null;
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("-b")) {
                if (ks != null || key_file != null) show();
                ks = DemoKeyStore.getMarionKeyStore();
            } else if (arg.equals("-t")) localfixed = true;
            else if (i + 1 < args.length && argtest(args, i + 1) != null) {
                String value = args[i + 1];
                if (arg.equals("-a")) keyAlias = value;
                else if (arg.equals("-k")) key_file = value;
                else if (arg.equals("-w")) storepassword = value;
                else if (arg.equals("-u")) signpassword = value;
                else show();
                i++;
            } else show();
        }
        if (ks == null) {
            if (key_file == null || storepassword == null || signpassword == null) show();
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(key_file), storepassword.toCharArray());
        } else {
            if (key_file != null || storepassword != null || signpassword != null) show();
            signpassword = DemoKeyStore.getSignerPassword();
        }
        String in_file = argtest(args, 0);
        String out_file = argtest(args, 1);

        KeyStoreSigner signer = new KeyStoreSigner(ks, null);
        signer.setKey(keyAlias, signpassword);

        test(in_file, out_file, signer, localfixed, false);

        System.out.println("Signed by:\n" + new CertificateInfo(signer.getCertificatePath()[0]).toString());
    }
}
