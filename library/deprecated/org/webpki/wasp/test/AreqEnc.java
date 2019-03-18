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
import java.util.GregorianCalendar;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.wasp.AuthenticationProfile;
import org.webpki.wasp.AuthenticationRequestEncoder;
import org.webpki.wasp.AuthenticationResponseDecoder;

public class AreqEnc {

    private static void show() {
        System.out.println("AreqEnc outfile [options]\n" +
                "  -F authfile  full round (all 4 steps)\n" +
                "  -H       use sha1 as message digest\n" +
                "  -B       use rsasha1 as signature method\n" +
                "  -Q       request prefix REQ\n" +
                "  -P       -F: RESP prefix\n" +
                "  -A       full cert path\n" +
                "  -D       signed keyinfo\n" +
                "  -I       sign request\n" +
                "  -R       request client-feature\n" +
                "  -T       set a fixed server time-stamp\n" +
                "  -t       set a fixed client time-stamp\n" +
                "  -i       set a fixed reference ID\n" +
                "  -f       set certificate filters\n" +
                "  -l       set languages = eng\n");
        System.exit(3);
    }


    public static void main(String args[]) throws Exception {
        if (args.length == 0) show();
        boolean lang = false;
        String authfile = null;
        boolean reqprefix = false;
        boolean respprefix = false;
        boolean fixed_client_time = false;
        boolean fixed_server_time = false;
        boolean certpath = false;
        boolean sha1DS = false;
        boolean rsasha1DS = false;
        boolean request_client_feature = false;
        boolean signrequest = false;
        boolean certflt = false;
        boolean signKI = false;
        boolean iddata = false;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("-I")) signrequest = true;
            else if (args[i].equals("-H")) sha1DS = true;
            else if (args[i].equals("-B")) rsasha1DS = true;
            else if (args[i].equals("-A")) certpath = true;
            else if (args[i].equals("-D")) signKI = true;
            else if (args[i].equals("-F")) {
                if (++i >= args.length || args[i].startsWith("-")) {
                    throw new IOException("Bad -F option");
                }
                authfile = args[i];
            } else if (args[i].equals("-Q")) reqprefix = true;
            else if (args[i].equals("-P")) respprefix = true;
            else if (args[i].equals("-R")) request_client_feature = true;
            else if (args[i].equals("-T")) fixed_server_time = true;
            else if (args[i].equals("-t")) fixed_client_time = true;
            else if (args[i].equals("-i")) iddata = true;
            else if (args[i].equals("-f")) certflt = true;
            else if (args[i].equals("-l")) lang = true;
            else show();
        }


        AuthenticationRequestEncoder areqenc = new AuthenticationRequestEncoder("https://example.com/home");

        AuthenticationProfile ap = areqenc.addAuthenticationProfile();

        ap.setExtendedCertPath(certpath);

        ap.setSignedKeyInfo(signKI);

        if (sha1DS) {
            ap.setDigestAlgorithm(HashAlgorithms.SHA1);
        }

        if (rsasha1DS) {
            ap.setSignatureAlgorithm(AsymSignatureAlgorithms.RSA_SHA1);
        }

        if (certflt) {
            for (CertificateFilter cf : SreqEnc.createCertificateFilters()) {
                areqenc.addCertificateFilter(cf);
            }
        }

        if (iddata) {
            areqenc.setID("I0762586222");
        }

        if (lang) {
            areqenc.setLanguages(new String[]{"eng"});
        }

        if (fixed_server_time) {
            areqenc.setServerTime(new GregorianCalendar(2005, 3, 10, 9, 30, 0).getTime());
        }

        if (reqprefix) {
            areqenc.setPrefix("REQ");
        }

        if (request_client_feature) {
            areqenc.requestClientPlatformFeature("http://xmlns.example.com/feature1");
        }

        if (signrequest) {
            KeyStoreSigner req_signer = new KeyStoreSigner(DemoKeyStore.getExampleDotComKeyStore(), null);
            req_signer.setKey(null, DemoKeyStore.getSignerPassword());
            areqenc.signRequest(req_signer);
        }

        byte[] data = areqenc.writeXML();
        ArrayUtil.writeFile(args[0], data);
        XMLSchemaCache sc = new XMLSchemaCache();
        sc.addWrapper(areqenc);
        sc.validate(data);

        if (authfile == null) return;

        // Simulate receival and transmit of data at the client

        KeyStoreSigner signer = new KeyStoreSigner(DemoKeyStore.getMarionKeyStore(), null);
        signer.setKey(null, DemoKeyStore.getSignerPassword());
        AresEnc.test(args[0], authfile, signer, fixed_client_time, respprefix);

        // Receive by requesting service

        AuthenticationResponseDecoder aresdec = AresDec.test(authfile);
        areqenc.checkRequestResponseIntegrity(aresdec, null);

        ArrayUtil.writeFile(authfile, aresdec.writeXML());

    }
}
