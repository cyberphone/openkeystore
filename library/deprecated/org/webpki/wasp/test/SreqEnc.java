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

import java.security.KeyStore;
import java.security.PrivateKey;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.webpki.util.ArrayUtil;

import org.webpki.wasp.prof.xds.XDSProfileRequestEncoder;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.CertificateSelection;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.AuthorityInfoAccessCAIssuersCache;
import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyContainerTypes;
import org.webpki.crypto.KeyUsageBits;

import org.webpki.wasp.SignatureRequestEncoder;
import org.webpki.wasp.SignatureResponseDecoder;
import org.webpki.wasp.TargetContainer;
import org.webpki.wasp.InternalDocument;
import org.webpki.wasp.DeletedDocument;


public class SreqEnc {
    private static void show() {
        System.out.println("SreqEnc outfile [options]\n" +
                "  -S       show message digests\n" +
                "  -W       simple 'Hello signature world!'\n" +
                "  -p       add a processing view\n" +
                "  -d       add a detail view\n" +
                "  -a       add an attachment\n" +
                "  -F sigfile  full round (all 4 steps)\n" +
                "  -H       use sha1 as message digest\n" +
                "  -B       use rsasha1 as signature method\n" +
                "  -n       prof: do not set a profile (use default XML)\n" +
                "  -c       prof: only CMS\n" +
                "  -2       prof: set two signature profiles (CMS, XMLDSig)\n" +
                "  -u       prof: set unsupported profile (may be combined with -2)\n" +
                "  -s       add a client platform request element\n" +
                "  -T       fixed server time\n" +
                "  -t       -F: fixed client time to response\n" +
                "  -C       copy data (by client)\n" +
                "  -Q       request prefix REQ\n" +
                "  -K       -F: copy data (by server)\n" +
                "  -P       -F: RESP prefix\n" +
                "  -Z       -F change data object to \"Internal\"\n" +
                "  -z       -F change data object to \"Deleted\"\n" +
                "  -A       full cert path\n" +
                "  -k       AIA extension rather than fat client-store\n" +
                "  -x       AIA extension pre-load\n" +
                "  -D       signed keyinfo\n" +
                "  -I       sign request\n" +
                "  -i       set a fixed reference ID\n" +
                "  -f       set certificate filters\n" +
                "  -l       set languages = eng\n");
        System.exit(3);
    }


    static CertificateFilter[] createCertificateFilters() throws Exception {
        KeyStore ks = DemoKeyStore.getMarionKeyStore();
        X509Certificate cert = (X509Certificate) ks.getCertificateChain("mykey")[1];

        CertificateFilter cf1 = new CertificateFilter()
                .setPolicyRules(new String[]{"1.25.453.22.22.88"})
                .setKeyUsageRules(new String[]{"digitalSignature"})
                .setFingerPrint(HashAlgorithms.SHA256.digest(cert.getEncoded()))  // CA
                .setIssuer(cert.getIssuerX500Principal());

        CertificateFilter cf2 = new CertificateFilter()
                .setFingerPrint(new byte[]{1, 4, 5, 3, 6, 7, 8, 3, 0, 3, 5, 6, 1, 4, 5, 3, 6, 7, 8, 3})
                .setIssuer(new X500Principal("CN=SuckerTrust GlobalCA, emailaddress=boss@fire.hell, c=TV"))
                .setExtendedKeyUsageRules(new String[]{"1.56.245.123"})
                .setKeyUsageRules(new String[]{"nonRepudiation", "-keyEncipherment"})
                .setEmail("try@this.com");
        return new CertificateFilter[]{cf1, cf2};
    }


    public static void main(String args[]) throws Exception {
        if (args.length == 0) show();
        boolean messagedigests = false;
        boolean lang = false;
        String sigfile = null;
        boolean reqprefix = false;
        boolean fixedtime = false;
        boolean respprefix = false;
        boolean attachment = false;
        boolean detail = false;
        boolean certpath = false;
        boolean processing = false;
        boolean simplesign = false;
        boolean copydata = false;
        boolean sha1DS = false;
        boolean rsasha1DS = false;
        boolean servertime = false;
        boolean twoprofs = false;
        boolean signrequest = false;
        boolean unsupprof = false;
        boolean aiaextension = false;
        boolean aiapreload = false;
        boolean internal = false;
        boolean deleted = false;
        boolean servercopy = false;
        boolean clientplatfreq = false;
        boolean certflt = false;
        boolean signKI = false;
        boolean iddata = false;
        boolean noset = false;
        boolean cms_only = false;
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("-p")) processing = true;
            else if (args[i].equals("-S")) messagedigests = true;
            else if (args[i].equals("-d")) detail = true;
            else if (args[i].equals("-2")) twoprofs = true;
            else if (args[i].equals("-s")) clientplatfreq = true;
            else if (args[i].equals("-T")) servertime = true;
            else if (args[i].equals("-I")) signrequest = true;
            else if (args[i].equals("-W")) simplesign = true;
            else if (args[i].equals("-H")) sha1DS = true;
            else if (args[i].equals("-B")) rsasha1DS = true;
            else if (args[i].equals("-a")) attachment = true;
            else if (args[i].equals("-A")) certpath = true;
            else if (args[i].equals("-k")) aiaextension = true;
            else if (args[i].equals("-x")) aiapreload = true;
            else if (args[i].equals("-D")) signKI = true;
            else if (args[i].equals("-u")) unsupprof = true;
            else if (args[i].equals("-F")) {
                if (++i >= args.length || args[i].startsWith("-")) {
                    throw new IOException("Bad -F option");
                }
                sigfile = args[i];
            } else if (args[i].equals("-n")) noset = true;
            else if (args[i].equals("-t")) fixedtime = true;
            else if (args[i].equals("-c")) cms_only = true;
            else if (args[i].equals("-C")) copydata = true;
            else if (args[i].equals("-Q")) reqprefix = true;
            else if (args[i].equals("-P")) respprefix = true;
            else if (args[i].equals("-K")) servercopy = true;
            else if (args[i].equals("-Z")) internal = true;
            else if (args[i].equals("-z")) deleted = true;
            else if (args[i].equals("-i")) iddata = true;
            else if (args[i].equals("-f")) certflt = true;
            else if (args[i].equals("-l")) lang = true;
            else show();
        }

        if (noset && (unsupprof || twoprofs || clientplatfreq || cms_only)) {
            throw new IOException("the -n option cannot be combined with other profile settings");
        }

        if (twoprofs && cms_only) {
            throw new IOException("the -2 option cannot be compined the -c option");
        }

        if ((internal || deleted) && !(servercopy || copydata)) {
            throw new IOException("Internal/Deleted requires a copy data option as well");
        }
        SignatureRequestEncoder sreqenc = null;
        if (simplesign) {
            sreqenc = new SignatureRequestEncoder("example.com", "https://example.com/submit");
            sreqenc.addTXTDocument(TargetContainer.MAIN_DOCUMENT, "Hello signature world!", null);
        } else {
            sreqenc = new SignatureRequestEncoder("mybank.com", "https://secure.mybank.com/paysrv");
            String content_id_uri = sreqenc.addDocument(TargetContainer.EMBEDDED_OBJECT, BankLogo.getGIFImage(),
                    "image/gif", null);
            sreqenc.addHTMLDocument(TargetContainer.MAIN_DOCUMENT, "<html><body><center><img src=\"" + content_id_uri +
                    "\"><p>Do you agree to pay<b> $100</b><br>to<b>" +
                    " 7-Eleven</b> ?</center></body></html>", null);
        }

        if (detail) {
            sreqenc.addHTMLDocument(TargetContainer.DETAIL_DOCUMENT, "<html><body>120 cans of Coca-Cola</body></html>", null);
        }

        if (processing) {
            sreqenc.addHTMLDocument(TargetContainer.PROCESSING_DOCUMENT, "<html><body><center>Processing!</center></body></html>", null);
        }

        if (attachment) {
            sreqenc.addAttachment("I am a nice guy, really!",
                    "text/plain",
                    null,
                    false,
                    "Declaration",
                    "declaration.txt",
                    false);
        }

        XDSProfileRequestEncoder xml = new XDSProfileRequestEncoder();

        xml.setExtendedCertPath(certpath);

        xml.setSignedKeyInfo(signKI);

        if (sha1DS) {
            xml.setDigestAlgorithm(HashAlgorithms.SHA1);
        }

        if (rsasha1DS) {
            xml.setSignatureAlgorithm(AsymSignatureAlgorithms.RSA_SHA1);
        }

//        CMSProfile0Request cms = new CMSProfile0Request ();

        if (twoprofs) {
            sreqenc.addSignatureProfile(xml);
//            sreqenc.addSignatureProfile (cms);
        } else if (!noset) {
            sreqenc.addSignatureProfile(xml);
//            sreqenc.addSignatureProfile (cms_only ? (SignatureProfile)cms : (SignatureProfile)xml);
        }

        if (unsupprof) {
            sreqenc.addSignatureProfile(new UnknownProfileRequestEncoder());
        }

        if (certflt) {
            for (CertificateFilter cf : createCertificateFilters()) {
                sreqenc.addCertificateFilter(cf);
            }
        }

        if (iddata) {
            sreqenc.setID("I0762586222");
        }

        if (lang) {
            sreqenc.setLanguages(new String[]{"eng"});
        }

        if (copydata) {
            sreqenc.setCopyData();
        }

        if (servertime) {
            sreqenc.setServerTime(new GregorianCalendar(2005, 3, 10, 9, 30, 0).getTime());
        }

        if (reqprefix) {
            sreqenc.setPrefix("REQ");
        }

        if (signrequest) {
            KeyStoreSigner signer = new KeyStoreSigner(simplesign ?
                    DemoKeyStore.getExampleDotComKeyStore()
                    :
                    DemoKeyStore.getMybankDotComKeyStore(), null);
            signer.setKey(null, DemoKeyStore.getSignerPassword());
            sreqenc.signRequest(signer);
        }

        if (messagedigests) {
            System.out.println(sreqenc.getDocumentSignatures().toString());
        }

        byte[] data = sreqenc.writeXML();
        ArrayUtil.writeFile(args[0], data);
        XMLSchemaCache sc = new XMLSchemaCache();
        sc.addWrapper(sreqenc);
        sc.validate(data);

        if (sigfile == null) return;

        // Simulate receival and transmit of data at the client
        KeyStore ks = DemoKeyStore.getMarionKeyStore();
        AuthorityInfoAccessCAIssuersCache aia_cache = null;
        if (aiaextension) {
            Certificate[] cert_list = ks.getCertificateChain("mykey");
            if (cert_list.length < 2) throw new IOException("Bad certpath");
            PrivateKey privk = (PrivateKey) ks.getKey("mykey", DemoKeyStore.getSignerPassword().toCharArray());
            ks.setKeyEntry("mykey",
                    privk,
                    DemoKeyStore.getSignerPassword().toCharArray(),
                    new Certificate[]{cert_list[0]});
            String[] aia_caissuers = CertificateUtil.getAIACAIssuers((X509Certificate) cert_list[0]);
            if (aia_caissuers == null) throw new IOException("AIA caissuers missing");
            aia_cache = new AuthorityInfoAccessCAIssuersCache();
            if (aiapreload) {
                aia_cache.preInitialize((X509Certificate) cert_list[1], aia_caissuers[0]);
            }
        }

        KeyStoreSigner signer = new KeyStoreSigner(ks, KeyContainerTypes.EMBEDDED);
        signer.setAuthorityInfoAccessCAIssuersHandler(aia_cache);
        CertificateFilter[] cf = SreqDec.test(args[0], false).getCertificateFilters();
        CertificateSelection cs = signer.getCertificateSelection(cf);
        String keys[] = cs.getKeyAliases();
        if (keys.length != 1) throw new IOException("None or multiple keys selected!");
        signer.setKey(keys[0], DemoKeyStore.getSignerPassword());
        SresEnc.test(args[0], sigfile, signer, fixedtime, 0, respprefix);

        // Receive by requesting service

        SignatureResponseDecoder sresdec = SresDec.test(sigfile, true);
        sresdec.checkRequestResponseIntegrity(sreqenc, null);

        if (servercopy) {
            sresdec.copyDocumentData(sreqenc);
        }

        if (internal) {
            sresdec.getDocumentData().replaceDocument(
                    new InternalDocument("urn:com:example/hjj",
                            sresdec.getDocumentData().getDocuments()[0].getContentID()));
        }

        if (deleted) {
            sresdec.getDocumentData().replaceDocument(
                    new DeletedDocument(null,
                            sresdec.getDocumentData().getDocuments()[1].getContentID()));
        }

        ArrayUtil.writeFile(sigfile, sresdec.writeXML());

    }

}
