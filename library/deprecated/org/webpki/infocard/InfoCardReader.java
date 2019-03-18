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
package org.webpki.infocard;

import java.io.IOException;

import java.util.Date;
import java.util.Set;
import java.util.EnumSet;

import java.security.cert.X509Certificate;

import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;

import org.webpki.crypto.VerifierInterface;

public class InfoCardReader
  {

    InfoCardDecoder card;


    private static void bad (String what) throws IOException
      {
        throw new IOException (what);
      }


    public static class InfoCardDecoder extends InfoCard
      {
        X509Certificate user_certificate;

        X509Certificate sts_certificate;

        String language = "en-us";

        Set<TokenType> tokens = EnumSet.noneOf (TokenType.class);

        String card_name;

        String card_id;

        String display_credential_hint;

        String issuer_uri;

        String endpoint_reference;

        String metadata_reference;

        String privacy_notice;

        Date time_issued;

        Date time_expires;

        Set<ClaimType> claims = EnumSet.noneOf (ClaimType.class);

        byte[] image_data;

        String image_mime;

        Boolean require_applies_to;

        boolean output_sts_identity;

        public InfoCardDecoder ()
          {
          }

        protected void fromXML (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

            /////////////////////////////////////////////////////////////////////////////////////////
            // Read the top level attributes
            /////////////////////////////////////////////////////////////////////////////////////////

            language = ah.getString (XML_LANG_ATTR);
          }
      }


    InfoCardReader () {}


    public InfoCardReader (byte[] data, VerifierInterface verifier) throws IOException
      {
        XMLSchemaCache cache = new XMLSchemaCache ();
        cache.addWrapper (InfoCardDecoder.class);
        Object o = cache.parse (data);
        if (!(o instanceof XMLSignatureWrapper))
          {
            bad ("Not signed???");
          }
        o = new XMLVerifier (verifier).verifyXMLWrapper ((XMLSignatureWrapper) o);
        if (!(o instanceof InfoCardDecoder))
          {
            bad ("Not an infocard???");
          }
      }


    public String getDisplayCredentialHint ()
      {
        return card.display_credential_hint;
      }


    public String getLanguage ()
      {
        return card.language;
      }

/*
    public InfoCardReader addClaim (ClaimType claim)
      {
        claims.add (claim);
        return this;
      }
*/

    public String getCardName ()
      {
        return card.card_name;
      }

/*
    public InfoCardReader setCardImage (byte[] image_data, String mimeType)
      {
        this.image_data = image_data;
        this.image_mime = mimeType;
        return this;
      }
*/
/*
    public InfoCardReader setTimeIssued (Date date)
      {
        time_issued = date;
        return this;
      }


    public InfoCardReader setTimeExpires (Date date)
      {
        time_expires = date;
        return this;
      }


    public InfoCardReader setRequireAppliesTo (boolean optional)
      {
        require_applies_to = new Boolean (optional);
        return this;
      }


    public InfoCardReader setPrivacyNotice (String uri)
      {
        privacy_notice = uri;
        return this;
      }


    public InfoCardReader setOutputSTSIdentity (boolean flag)
      {
        output_sts_identity = flag;
        return this;
      }


    public InfoCardReader addTokenType (TokenType token_type)
      {
        tokens.add (token_type);
        return this;
      }
*/
  }
