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

import java.util.HashMap;
import java.util.Date;
import java.util.Set;
import java.util.EnumSet;

import java.security.cert.X509Certificate;

import org.webpki.util.MimeTypedObject;
import org.webpki.util.Base64;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;


public class InfoCardWriter
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

    HashMap<ClaimType,String>descriptions = new HashMap<ClaimType,String> ();

    MimeTypedObject card_image;

    Boolean require_applies_to;

    boolean output_sts_identity;



    private static void bad (String what) throws IOException
      {
        throw new IOException (what);
      }


    class InfoCardEncoder extends InfoCard
      {

        private void initNS (DOMWriterHelper wr, String prefix, String namespace) throws IOException
          {
            wr.current ().setAttributeNS ("http://www.w3.org/2000/xmlns/", (prefix == null) ? "xmlns" : "xmlns:" + prefix, namespace);
          }


        protected void toXML (DOMWriterHelper wr) throws IOException
          {
            wr.setPrettyPrinting (false);
            wr.initializeRootObject (INFOCARD_NS_PREFIX);

            //////////////////////////////////////////////////////////////////////////
            // Set top-level attributes
            //////////////////////////////////////////////////////////////////////////
            wr.setStringAttribute (XML_LANG_ATTR, language);

            initNS (wr, WSS_SECEXT_NS_PREFIX, WSS_SECEXT_NS);
            initNS (wr, WS_ADDR_NS_PREFIX, WS_ADDR_NS);
            initNS (wr, META_EXHG_NS_PREFIX, META_EXHG_NS);
            initNS (wr, WS_TRUST_NS_PREFIX, WS_TRUST_NS);
            if (output_sts_identity)
              {
                initNS (wr, WSS_ID_NS_PREFIX, WSS_ID_NS);
              }

            //////////////////////////////////////////////////////////////////////////
            // Output card header
            //////////////////////////////////////////////////////////////////////////
            wr.addChildElement (INFORMATION_CARD_REFERENCE_ELEM);
            wr.addString (CARD_ID_ELEM, card_id);
            wr.addString (CARD_VERSION_ELEM, "1");
            wr.getParent ();

            //////////////////////////////////////////////////////////////////////////
            // Output optional user-oriented card details
            //////////////////////////////////////////////////////////////////////////
            if (card_name != null)
              {
                wr.addString (CARD_NAME_ELEM, card_name);
              }

            if (card_image != null)
              {
                wr.addBinary (CARD_IMAGE_ELEM, card_image.getData ());
                wr.setStringAttribute (MIME_TYPE_ATTR, card_image.getMimeType ());
              }

            //////////////////////////////////////////////////////////////////////////
            // Output issuer data
            //////////////////////////////////////////////////////////////////////////
            wr.addString (ISSUER_ELEM, issuer_uri);
            wr.addDateTime (TIME_ISSUED_ELEM, time_issued);
            if (time_expires != null)
              {
                wr.addDateTime (TIME_EXPIRES_ELEM, time_expires);
              }

            //////////////////////////////////////////////////////////////////////////
            // Begin token service list
            //////////////////////////////////////////////////////////////////////////
            wr.addChildElement (TOKEN_SERVICE_LIST_ELEM);
            wr.addChildElement (TOKEN_SERVICE_ELEM);

            //////////////////////////////////////////////////////////////////////////
            // Output end-point data
            //////////////////////////////////////////////////////////////////////////
            wr.pushPrefix (WS_ADDR_NS_PREFIX);
            wr.addChildElementNS (WS_ADDR_NS, ENDPOINT_REFERENCE_ELEM);
            wr.addString (ADDRESS_ELEM, endpoint_reference);
            wr.addChildElement (METADATA_ELEM);
            wr.pushPrefix (META_EXHG_NS_PREFIX);
            wr.addChildElementNS (META_EXHG_NS, METADATA_ELEM);
            wr.addChildElement (METADATA_SECTION_ELEM);
            wr.addChildElement (METADATA_REFERENCE_ELEM);
            wr.pushPrefix (WS_ADDR_NS_PREFIX);
            wr.addString (ADDRESS_ELEM, metadata_reference);
            wr.popPrefix ();
            wr.getParent ();
            wr.getParent ();
            wr.getParent ();
            wr.popPrefix ();
            wr.getParent ();
            if (output_sts_identity)
              {
                wr.pushPrefix (WSS_ID_NS_PREFIX);
                wr.addChildElementNS (WSS_ID_NS, IDENTITY_ELEM);
                wr.pushPrefix (XMLSignatureWrapper.XML_DSIG_NS_PREFIX);
                wr.addChildElement (XMLSignatureWrapper.KEY_INFO_ELEM);
                XMLSignatureWrapper.writeX509DataSubset (wr, new X509Certificate[] {sts_certificate});
                wr.getParent ();
                wr.popPrefix ();
                wr.getParent ();
                wr.popPrefix ();
              }
            wr.getParent ();
            wr.popPrefix ();

            //////////////////////////////////////////////////////////////////////////
            // Output user credential portion
            //////////////////////////////////////////////////////////////////////////
            wr.addChildElement (USER_CREDENTIAL_ELEM);
            if (display_credential_hint != null)
              {
                wr.addString (DISPLAY_CREDENTIAL_HINT_ELEM, display_credential_hint);
              }
            wr.addChildElement (X509V3_CREDENTIAL_ELEM);

            wr.pushPrefix (XMLSignatureWrapper.XML_DSIG_NS_PREFIX);
            wr.addChildElement (XMLSignatureWrapper.X509_DATA_ELEM);

            wr.pushPrefix (WSS_SECEXT_NS_PREFIX);
            wr.addStringNS (WSS_SECEXT_NS, KEY_IDENTIFIER_ELEM,
                            new Base64 (false).getBase64StringFromBinary (CertificateUtil.getCertificateSHA1 (user_certificate)));
            wr.setStringAttribute (ENCODING_TYPE_ATTR, ENC_TYPE_URI_B64_BIN);
            wr.setStringAttribute (VALUE_TYPE_ATTR, VALUE_TYPE_URI_THUMB);
            wr.popPrefix ();

            wr.getParent ();
            wr.popPrefix ();

            wr.getParent ();
            wr.getParent ();

            //////////////////////////////////////////////////////////////////////////
            // End token service list
            //////////////////////////////////////////////////////////////////////////
            wr.getParent ();
            wr.getParent ();

            //////////////////////////////////////////////////////////////////////////
            // Output token list portion
            //////////////////////////////////////////////////////////////////////////
            wr.addChildElement (SUPPORTED_TOKEN_TYPE_LIST_ELEM);
            wr.pushPrefix (WS_TRUST_NS_PREFIX);
            for (TokenType tt : tokens)
              {
                wr.addStringNS (WS_TRUST_NS, TOKEN_TYPE_ELEM, tt.getXMLName ());
              }
            wr.popPrefix ();
            wr.getParent ();

            //////////////////////////////////////////////////////////////////////////
            // Output claims
            //////////////////////////////////////////////////////////////////////////
            if (claims.isEmpty ())
              {
                bad ("There must be at least one claim!");
              }
            wr.addChildElement (SUPPORTED_CLAIM_TYPE_LIST_ELEM);
            for (ClaimType ct : claims)
              {
                wr.addChildElement (SUPPORTED_CLAIM_TYPE_ELEM);
                wr.setStringAttribute (URI_ATTR, ct.getXMLName ());
                wr.addString (DISPLAY_TAG_ELEM, ct.getDisplayTag ());
                String description = descriptions.get (ct);
                if (description != null)
                  {
                    wr.addString (DESCRIPTION_ELEM, description);
                  }
                wr.getParent ();
              }
            wr.getParent ();

            //////////////////////////////////////////////////////////////////////////
            // "RequireAppliesTo" handling
            //////////////////////////////////////////////////////////////////////////
            if (require_applies_to != null)
              {
                wr.addChildElement (REQUIRE_APPLIES_TO_ELEM);
                wr.setBooleanAttribute (OPTIONAL_ATTR, require_applies_to);
                wr.getParent ();
              }

            //////////////////////////////////////////////////////////////////////////
            // "PrivacyNotice" handling
            //////////////////////////////////////////////////////////////////////////
            if (privacy_notice != null)
              {
                wr.addString (PRIVACY_NOTICE_ELEM, privacy_notice);
              }
          }
      }

    InfoCardEncoder card = new InfoCardEncoder ();


    InfoCardWriter () {}


    public InfoCardWriter (X509Certificate user_certificate,
                           TokenType token_type,
                           String card_id,
                           String issuer_uri,
                           String endpoint_reference,
                           String metadata_reference)
      {
        time_issued = user_certificate.getNotBefore ();
        time_expires = user_certificate.getNotAfter ();
        this.user_certificate = user_certificate;
        this.tokens.add (token_type);
        this.card_id = card_id;
        this.issuer_uri = issuer_uri;
        this.endpoint_reference = endpoint_reference;
        this.metadata_reference = metadata_reference;
      }


    public byte[] getInfoCard (SignerInterface signer) throws IOException
      {
        sts_certificate = signer.getCertificatePath ()[0];
        XMLSigner xmls = new XMLSigner (signer);
        return xmls.signXMLWrapper (card, "_Object_InfoCard").writeXML ();
      }


    public InfoCardWriter setDisplayCredentialHint (String hint)
      {
        display_credential_hint = hint;
        return this;
      }


    public InfoCardWriter setLanguage (String language)
      {
        this.language = language;
        return this;
      }


    public InfoCardWriter addClaim (ClaimType claim, String description)
      {
        descriptions.put (claim, description);
        claims.add (claim);
        return this;
      }

    public InfoCardWriter addClaim (ClaimType claim)
      {
        return addClaim (claim, null);
      }


    public InfoCardWriter setCardName (String name)
      {
        card_name = name;
        return this;
      }


    public InfoCardWriter setCardImage (MimeTypedObject image)
      {
        card_image = image;
        return this;
      }


    public InfoCardWriter setTimeIssued (Date date)
      {
        time_issued = date;
        return this;
      }


    public InfoCardWriter setTimeExpires (Date date)
      {
        time_expires = date;
        return this;
      }


    public InfoCardWriter setRequireAppliesTo (boolean optional)
      {
        require_applies_to = new Boolean (optional);
        return this;
      }


    public InfoCardWriter setPrivacyNotice (String uri)
      {
        privacy_notice = uri;
        return this;
      }


    public InfoCardWriter setOutputSTSIdentity (boolean flag)
      {
        output_sts_identity = flag;
        return this;
      }


    public InfoCardWriter addTokenType (TokenType token_type)
      {
        tokens.add (token_type);
        return this;
      }

  }
