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
package org.webpki.xmldsig;

import java.io.IOException;
import java.io.FileInputStream;

import java.security.KeyStore;


import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.crypto.KeyStoreSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLEnvelopedInput;

public class CreateES {
    private static final int OUTFILE = 0;
    private static final int INFILE = 1;
    private static final int WRAPPER = 2;
    private static final int KEYSTORE = 3;
    private static final int STORETYPE = 4;
    private static final int KEYALIAS = 5;
    private static final int STOREPASS = 6;
    private static final int SIGNPASS = 7;

    private static void show() {
        System.out.println("CreateES output-xml-file input-xml-file wrapper-class " +
                "keystore storetype keyalias storepass signpass\n");
        System.exit(3);
    }

    public static void main(String args[]) throws Exception {
        if (args.length != 8) show();


        XMLSchemaCache sc = new XMLSchemaCache();
        sc.addWrapper(XMLSignatureWrapper.class);
        sc.addWrapper(Class.forName(args[WRAPPER], true, ClassLoader.getSystemClassLoader()).asSubclass(XMLObjectWrapper.class));

        XMLObjectWrapper o = sc.parse(ArrayUtil.readFile(args[INFILE]));

        KeyStore ks = KeyStore.getInstance(args[STORETYPE]);
        ks.load(new FileInputStream(args[KEYSTORE]), args[STOREPASS].toCharArray());

        KeyStoreSigner signer = new KeyStoreSigner(ks, null);
        signer.setKey(args[KEYALIAS], args[SIGNPASS]);

        XMLSigner xmlsign = new XMLSigner(signer);

        if (!(o instanceof XMLEnvelopedInput)) {
            throw new IOException("Wrapper class must implement XMLEnvelopedInput");
        }

        xmlsign.createEnvelopedSignature((XMLEnvelopedInput) o);

        ArrayUtil.writeFile(args[OUTFILE], o.writeXML());

    }

}
