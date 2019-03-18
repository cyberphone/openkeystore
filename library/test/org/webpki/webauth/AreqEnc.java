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

import java.io.IOException;

import java.security.Provider;
import java.security.Security;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONOutputFormats;

import org.webpki.webauth.AuthenticationRequestDecoder;
import org.webpki.webauth.AuthenticationRequestEncoder;
import org.webpki.webauth.AuthenticationResponseDecoder;

public class AreqEnc {
    static StringBuilder info_string;

    static int info_lengthp2;

    static void printHeader() {
        for (int i = 0; i < info_lengthp2; i++) {
            info_string.append('=');
        }
        info_string.append('\n');
    }

    static void printInfo(String info) {
        info_string = new StringBuilder("\n\n");
        info_lengthp2 = info.length() + 4;
        printHeader();
        info_string.append("= ").append(info).append(" =\n");
        printHeader();
        System.out.println(info_string.toString());
    }

    static void installOptionalBCProvider() {
        @SuppressWarnings("rawtypes")
        Class bc = null;
        try {
            bc = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
        } catch (ClassNotFoundException e) {
            printInfo("BouncyCastle provider not in path - Using the platform provider");
            return;
        }
        try {
            Security.insertProviderAt((Provider) bc.newInstance(), 1);
            printInfo("Installed BouncyCastle as first provider");
        } catch (Exception e) {
            printInfo("Failed to install BouncyCastle!");
        }
    }

    static {
        installOptionalBCProvider();
    }

    private static void show() {
        System.out.println("AreqEnc outfile [options]\n" +
                "  -F authfile  full round (all 4 steps)\n" +
                "  -B       use rsasha1 as signature method\n" +
                "  -A       full cert path\n" +
                "  -I       sign request\n" +
                "  -R       request client-feature\n" +
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
        boolean fixed_client_time = false;
        boolean certpath = false;
        boolean rsasha1DS = false;
        boolean request_client_feature = false;
        boolean signrequest = false;
        boolean certflt = false;
        boolean iddata = false;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("-I")) signrequest = true;
            else if (args[i].equals("-B")) rsasha1DS = true;
            else if (args[i].equals("-A")) certpath = true;
            else if (args[i].equals("-F")) {
                if (++i >= args.length || args[i].startsWith("-")) {
                    throw new IOException("Bad -F option");
                }
                authfile = args[i];
            } else if (args[i].equals("-R")) request_client_feature = true;
            else if (args[i].equals("-t")) fixed_client_time = true;
            else if (args[i].equals("-i")) iddata = true;
            else if (args[i].equals("-f")) certflt = true;
            else if (args[i].equals("-l")) lang = true;
            else show();
        }


        AuthenticationRequestEncoder areqenc = new AuthenticationRequestEncoder("https://example.com/home", null);

        if (certpath) {
            areqenc.setExtendedCertPath(true);
        }

        if (rsasha1DS) {
            areqenc.addSignatureAlgorithm(AsymSignatureAlgorithms.RSA_SHA1);
        } else {
            areqenc.addSignatureAlgorithm(AsymSignatureAlgorithms.RSA_SHA256);
            areqenc.addSignatureAlgorithm(AsymSignatureAlgorithms.ECDSA_SHA256);
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
            areqenc.setPreferredLanguages(new String[]{"eng"});
        }

        if (request_client_feature) {
            areqenc.requestClientFeature("http://xmlns.example.com/feature1");
        }

        if (signrequest) {
            KeyStoreSigner req_signer = new KeyStoreSigner(DemoKeyStore.getExampleDotComKeyStore(), null);
            req_signer.setKey(null, DemoKeyStore.getSignerPassword());
// TODO
            req_signer.setExtendedCertPath(true);
            areqenc.setRequestSigner(req_signer);
        }

        byte[] data = areqenc.serializeJSONDocument(JSONOutputFormats.PRETTY_PRINT);
        ArrayUtil.writeFile(args[0], data);
        JSONDecoderCache sc = new JSONDecoderCache();
        sc.addToCache(AuthenticationRequestDecoder.class);
        sc.parse(data);

        if (authfile == null) return;

        // Simulate receival and transmit of data at the client

        KeyStoreSigner signer = new KeyStoreSigner(DemoKeyStore.getMarionKeyStore(), null);
        signer.setKey(null, DemoKeyStore.getSignerPassword());
        AresEnc.test(args[0], authfile, signer, fixed_client_time);

        // Receive by requesting service

        AuthenticationResponseDecoder aresdec = AresDec.test(authfile);
        areqenc.checkRequestResponseIntegrity(aresdec, null);

        ArrayUtil.writeFile(authfile, aresdec.getWriter().serializeToBytes(JSONOutputFormats.PRETTY_PRINT));

    }
}
