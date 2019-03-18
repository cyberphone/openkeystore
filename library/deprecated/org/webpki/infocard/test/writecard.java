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
package org.webpki.infocard.test;

import java.security.cert.X509Certificate;

import org.webpki.util.ArrayUtil;
import org.webpki.util.ImageData;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.wasp.test.BankLogo;

import org.webpki.crypto.KeyStoreSigner;

import org.webpki.infocard.InfoCardWriter;
import org.webpki.infocard.TokenType;
import org.webpki.infocard.ClaimType;

public class writecard
  {

    private static void show ()
      {
        System.out.println ("writecard out_file\n");
        System.exit (3);
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();

        InfoCardWriter icw = new InfoCardWriter ((X509Certificate) DemoKeyStore.getMarionKeyStore ().getCertificate ("mykey"),
                                                 TokenType.SAML_1_0,
                                                 "http://infocard.example.com/1234567",
                                                 "http://example.com",
                                                 "https://sts.example.com/tokenservice",
                                                 "https://sts.example.com/metadata");
        icw.setDisplayCredentialHint ("Insert smart card")
           .addClaim (ClaimType.EMAIL_ADDRESS, "boss@fire.hell")
           .addClaim (ClaimType.COUNTRY)
           .setCardName ("WebPKI.org")
           .setCardImage (new ImageData (BankLogo.getGIFImage (), "image/gif"))
  //         .setTimeExpires (DOMReaderHelper.parseDateTime ("2017-11-12T21:03:24Z").getTime ())
           .setRequireAppliesTo (true)
           .setOutputSTSIdentity (true)
           .setPrivacyNotice ("http://example.com/priv")
           .addTokenType (TokenType.SAML_2_0);


        KeyStoreSigner signer = new KeyStoreSigner (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        ArrayUtil.writeFile (args[0], icw.getInfoCard (signer));
      }
  }
