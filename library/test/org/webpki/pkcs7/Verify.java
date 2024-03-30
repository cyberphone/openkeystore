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
package org.webpki.pkcs7;

import java.util.Arrays;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.KeyStoreVerifier;

import org.webpki.util.IO;

public class Verify {
    public static void main(String[] args) throws Exception {
        if (args.length != 2 && (args.length != 3 || !args[2].equals("-d"))) {
            System.out.println("Verify reffile signaturefile [-d]\n\n" +
                    "   reffile       : where raw data is read and compared\n" +
                    "   signaturefile : PKCS #7 signature\n" +
                    "   -d            : detached signature\n");
            System.exit(3);
        }
        KeyStoreVerifier verifier = new KeyStoreVerifier(DemoKeyStore.getCAKeyStore());
        PKCS7Verifier pkcs7 = new PKCS7Verifier(verifier);
        verifier.setTrustedRequired(false);
        if (args.length == 2) {
            byte[] read_data = pkcs7.verifyMessage(IO.readFile(args[1]));
            if (!Arrays.equals(read_data, IO.readFile(args[0]))) {
                throw new Exception("Data mismatch");
            }
        } else {
            pkcs7.verifyDetachedMessage(IO.readFile(args[0]), IO.readFile(args[1]));
        }
        System.out.println("\nVERIFICATION SUCCESSFUL\n\n" + new CertificateInfo(verifier.getCertificatePath()[0]).toString());
    }
}
