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
package org.webpki.pdf;


import java.io.IOException;

import org.webpki.util.ArrayUtil;
import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.pdf.PDFSigner;


public class Sign {

    public static void main(String argv[]) throws IOException {
        if (argv.length < 6 ||
                (!argv[0].equals("c") && !argv[0].equals("s")) ||
                (!argv[1].equals("v") && !argv[1].equals("i")) ||
                (!argv[2].equals("p") && !argv[2].equals("n")) ||
                (!argv[3].equals("m") && !argv[3].equals("e"))) {
            System.out.println("PDFSigner c|s v|i p|n m|e infile outfile [attachments]...\n\n" +
                    "   c = Certified document, s = Signed document\n" +
                    "   v = Visible signature, i = Invsible signature\n" +
                    "   p = Certificate path included, n = No path included (only signer certificate)\n" +
                    "   m = Marion Anderson is signing, e = Example.com is signing");
            System.exit(3);
        }
        KeyStoreSigner signer = new KeyStoreSigner(argv[3].equals("m") ?
                DemoKeyStore.getMarionKeyStore() :
                DemoKeyStore.getExampleDotComKeyStore(), null);
        signer.setKey(null, DemoKeyStore.getSignerPassword());
        PDFSigner ds = new PDFSigner(signer);

        if (argv[1].equals("v")) {
            ds.setSignatureGraphics(true);
        }
        if (argv[2].equals("p")) {
            signer.setExtendedCertPath(true);
        }
        for (int i = 6; i < argv.length; i++) {
            ds.addAttachment(argv[i], "Attachment #" + (i - 5), ArrayUtil.readFile(argv[i]));
        }
        ArrayUtil.writeFile(argv[5], ds.addDocumentSignature(ArrayUtil.readFile(argv[4]), argv[0].equals("c")));
    }

}
