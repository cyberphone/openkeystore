// This is the base class which is extended by "InfoCard" Encoder and Decoder
package org.webpki.infocard;

import java.io.IOException;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;


abstract class InfoCard extends XMLObjectWrapper 
  {
    InfoCard () {}

    public static final String INFOCARD_NS   = "http://schemas.xmlsoap.org/ws/2005/05/identity";
    static final String INFOCARD_NS_PREFIX   = "ic";

    static final String WSS_SECEXT_NS        = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    static final String WSS_SECEXT_NS_PREFIX = "wsse";

    static final String WSS_ID_NS            = "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity";
    static final String WSS_ID_NS_PREFIX     = "wsid";

    static final String WS_TRUST_NS          = "http://schemas.xmlsoap.org/ws/2005/02/trust";
    static final String WS_TRUST_NS_PREFIX   = "wst";

    static final String WS_ADDR_NS           = "http://www.w3.org/2005/08/addressing";
    static final String WS_ADDR_NS_PREFIX    = "wsa";

    static final String META_EXHG_NS         = "http://schemas.xmlsoap.org/ws/2004/09/mex";
    static final String META_EXHG_NS_PREFIX  = "mex";

    static final String INFORMATION_CARD_ELEM           = "InformationCard";

    static final String INFORMATION_CARD_REFERENCE_ELEM = "InformationCardReference";

    static final String CARD_ID_ELEM                    = "CardId";

    static final String CARD_VERSION_ELEM               = "CardVersion";

    static final String CARD_NAME_ELEM                  = "CardName";

    static final String CARD_IMAGE_ELEM                 = "CardImage";

    static final String ISSUER_ELEM                     = "Issuer";

    static final String TIME_ISSUED_ELEM                = "TimeIssued";

    static final String TIME_EXPIRES_ELEM               = "TimeExpires";

    static final String TOKEN_SERVICE_LIST_ELEM         = "TokenServiceList";

    static final String TOKEN_SERVICE_ELEM              = "TokenService";

    static final String ENDPOINT_REFERENCE_ELEM         = "EndpointReference";

    static final String ADDRESS_ELEM                    = "Address";

    static final String METADATA_ELEM                   = "Metadata";

    static final String METADATA_SECTION_ELEM           = "MetadataSection";

    static final String METADATA_REFERENCE_ELEM         = "MetadataReference";

    static final String IDENTITY_ELEM                   = "Identity";

    static final String USER_CREDENTIAL_ELEM            = "UserCredential";

    static final String DISPLAY_CREDENTIAL_HINT_ELEM    = "DisplayCredentialHint";

    static final String X509V3_CREDENTIAL_ELEM          = "X509V3Credential";

    static final String KEY_IDENTIFIER_ELEM             = "KeyIdentifier";

    static final String SUPPORTED_TOKEN_TYPE_LIST_ELEM  = "SupportedTokenTypeList";

    static final String TOKEN_TYPE_ELEM                 = "TokenType";

    static final String SUPPORTED_CLAIM_TYPE_ELEM       = "SupportedClaimType";

    static final String DISPLAY_TAG_ELEM                = "DisplayTag";

    static final String DESCRIPTION_ELEM                = "Description";

    static final String SUPPORTED_CLAIM_TYPE_LIST_ELEM  = "SupportedClaimTypeList";

    static final String REQUIRE_APPLIES_TO_ELEM         = "RequireAppliesTo";

    static final String PRIVACY_NOTICE_ELEM             = "PrivacyNotice";
    
    static final String XML_LANG_ATTR                   = "xml:lang";

    static final String MIME_TYPE_ATTR                  = "MimeType";

    static final String OPTIONAL_ATTR                   = "Optional";

    static final String URI_ATTR                        = "Uri";

    static final String ENCODING_TYPE_ATTR              = "EncodingType";
    static final String ENC_TYPE_URI_B64_BIN            = "http://docs.oasis-open.org/wss/2004/01/oasis200401-wsssoap-message-security-1.0#Base64Binary";

    static final String VALUE_TYPE_ATTR                 = "ValueType";
    static final String VALUE_TYPE_URI_THUMB            = "http://docs.oasis-open.org/wss/2004/xx/oasis-2004xx-wss-soap-message-security-1.1#ThumbprintSHA1";


    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema ("reduced-wss-id.xsd");
        addSchema ("reduced-meta-exhg.xsd");
        addSchema ("reduced-ws-addr.xsd");
        addSchema ("reduced-wss-ext.xsd");
        addSchema ("reduced-ws-trust.xsd");
        addSchema ("reduced-xml.xsd");
        addSchema ("infocard-x509.xsd");
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return INFOCARD_NS;
      }

    
    public String element ()
      {
        return INFORMATION_CARD_ELEM;
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }

  }
