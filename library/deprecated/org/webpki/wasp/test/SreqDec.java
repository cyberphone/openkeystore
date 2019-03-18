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


import org.webpki.util.StringUtil;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.KeyContainerTypes;

import org.webpki.wasp.prof.xds.XDSProfileRequestDecoder;  // Mandatory profile

import org.webpki.wasp.SignatureRequestDecoder;
import org.webpki.wasp.SignatureProfileDecoder;


public class SreqDec {

    private static void show() {
        System.out.println("SreqDec inputfile [options]\n" +
                "   -n   No object data output\n" +
                "   -d   Debug\n");
        System.exit(3);
    }

    static void printcf(CertificateFilter cf, StringBuilder s) {
        s.append("\nCERTFILTER:");
        if (cf.getFingerPrint() != null)
            s.append("\nSha1=" + DebugFormatter.getHexString(cf.getFingerPrint()));
        if (cf.getIssuerRegEx() != null) s.append("\nIssuer=" + cf.getIssuerRegEx());
        if (cf.getSubjectRegEx() != null) s.append("\nSubject=" + cf.getSubjectRegEx());
        if (cf.getSerialNumber() != null) s.append("\nSerial=" + cf.getSerialNumber());
        if (cf.getPolicyRules() != null) s.append("\nPolicy=" + cf.getPolicyRules());
        if (cf.getKeyUsageRules() != null) s.append("\nKeyUsage=" + cf.getKeyUsageRules());
        if (cf.getExtendedKeyUsageRules() != null)
            s.append("\nExtKeyUsage=" + cf.getExtendedKeyUsageRules());
        s.append("\nCERTFILTER\n");
    }

    private static void print(String name, SignatureRequestDecoder.BaseDocument d, StringBuilder s) throws Exception {
        if (d != null) {
            s.append("\n" + name + ":\nURI=" + d.getContentID() +
                    "\nMIMEType=" + d.getMimeType() + "\nValue=\n" +
                    new String(d.getData(), "UTF-8") + "\n" +
                    (d instanceof SignatureRequestDecoder.Attachment ?
                            "ProviderOriginated=" +
                                    ((SignatureRequestDecoder.Attachment) d).getProviderOriginated() + "\n" +
                                    "Description=" +
                                    ((SignatureRequestDecoder.Attachment) d).getDescription() + "\n" +
                                    "File=" +
                                    ((SignatureRequestDecoder.Attachment) d).getFile() + "\n" +
                                    "MustAccess=" +
                                    ((SignatureRequestDecoder.Attachment) d).getMustAccess() + "\n" : "") + name + "\n");
        }
    }

    static SignatureRequestDecoder test(String file, boolean outdata) throws Exception {

        byte[] data = ArrayUtil.readFile(file);

        XMLSchemaCache schema_cache = new XMLSchemaCache();
        schema_cache.addWrapper(SignatureRequestDecoder.class);
        schema_cache.addWrapper(XDSProfileRequestDecoder.class);

        SignatureRequestDecoder sreq = (SignatureRequestDecoder) schema_cache.parse(data);

        boolean signed = sreq.isSigned();

        KeyStoreVerifier verifier = new KeyStoreVerifier(DemoKeyStore.getCAKeyStore());
        verifier.setTrustedRequired(false);

        if (signed) {
            sreq.verifySignature(verifier);
        }

        StringBuilder s = new StringBuilder();

        for (SignatureProfileDecoder spd : sreq.getSignatureProfilesDecoders()) {
            s.append("\nSIGNATUREPROFILE:\n" + spd + "\nSIGNATUREPROFILE\n");
        }

        for (CertificateFilter cf : sreq.getCertificateFilters()) {
            printcf(cf, s);
        }

        print("MAIN_VIEW", sreq.getMainDocument(), s);

        print("DETAIL_VIEW", sreq.getDetailDocument(), s);

        print("PROCESSING_VIEW", sreq.getProcessingDocument(), s);

        for (SignatureRequestDecoder.BaseDocument d : sreq.getEmbeddedObjects()) {
            print("EMBEDDED", d, s);
        }

        for (SignatureRequestDecoder.BaseDocument d : sreq.getAttachments()) {
            print("ATTACHMENT", d, s);
        }

        s.append("\nID=" + sreq.getID() + "\n");

        if (sreq.getLanguages() != null)
            s.append("\nLanguages=" + StringUtil.tokenList(sreq.getLanguages()) + "\n");

        s.append("\nMESSAGEDIGEST:\n" + sreq.getDocumentSignatures(null, null) + "\nMESSAGEDIGEST\n");

        if (signed) {
            s.append("\nSIGNATURE\n" + verifier.getSignerCertificate().toString() + "\nSIGNATURE");
        }

        if (outdata) {
            System.out.println(s.toString());
        }
        return sreq;
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
