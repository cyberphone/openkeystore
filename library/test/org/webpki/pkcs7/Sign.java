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
package org.webpki.pkcs7;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.util.ArrayUtil;
import org.webpki.pkcs7.PKCS7Signer;

public class Sign {
    public static void main(String[] args) throws Exception {
        if (args.length != 2 && (args.length != 3 || !args[2].equals("-d"))) {
            System.out.println("Sign outputfile inputfile [-d]\n\n" +
                    "   outputfile: where signed data is written\n" +
                    "   inputfile : where data to be signed is read\n" +
                    "   -d        : detached signature\n");
            System.exit(3);
        }
        KeyStoreSigner signer = new KeyStoreSigner(DemoKeyStore.getMarionKeyStore(), null);
        signer.setKey(null, DemoKeyStore.getSignerPassword());
        PKCS7Signer pkcs7 = new PKCS7Signer(signer);
//        pkcs7.setSignatureAlgorithm (org.webpki.crypto.SignatureAlgorithms.RSA_SHA256);
        ArrayUtil.writeFile(args[0],
                args.length == 2 ?
                        pkcs7.signMessage(ArrayUtil.readFile(args[1]))
                        :
                        pkcs7.signDetachedMessage(ArrayUtil.readFile(args[1])));
        System.out.println("\nSIGNING SUCCESSFUL\n\n" + new CertificateInfo(signer.getCertificatePath()[0]).toString());
    }
}
