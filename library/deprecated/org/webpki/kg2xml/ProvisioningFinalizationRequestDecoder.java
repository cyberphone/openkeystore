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
package org.webpki.kg2xml;

import java.io.IOException;

import java.util.Vector;

import java.security.cert.X509Certificate;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.VerifierInterface;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class ProvisioningFinalizationRequestDecoder extends ProvisioningFinalizationRequest
  {
    public class PostOperation
      {
        public static final int DELETE_KEY            = 0;
        public static final int UNLOCK_KEY            = 1;
        public static final int UPDATE_KEY            = 2;
        public static final int CLONE_KEY_PROTECTION  = 3;
        
        String clientSessionId;
        
        String serverSessionId;
        
        byte[] mac;
        
        byte[] certificateFingerprint;
        
        byte[] authorization;
        
        int postOperation;
        
        PostOperation (String clientSessionId,
                       String serverSessionId,
                       byte[] certificateFingerprint,
                       byte[] authorization,
                       byte[] mac,
                       int postOperation)
          {
            this.clientSessionId = clientSessionId;
            this.serverSessionId = serverSessionId;
            this.certificateFingerprint = certificateFingerprint;
            this.authorization = authorization;
            this.mac = mac;
            this.postOperation = postOperation;
          }
        
        public byte[] getMac ()
          {
            return mac;
          }
        
        public byte[] getCertificateFingerprint ()
          {
            return certificateFingerprint;
          }
        
        public byte[] getAuthorization ()
          {
            return authorization;
          }
        
        public int getPostOperation ()
          {
            return postOperation;
          }
        
        public String getClientSessionId ()
          {
            return clientSessionId;
          }
        
        public String getServerSessionId ()
          {
            return serverSessionId;
          }
  
      }

    public abstract class Extension
      {
  
        String type;
        
        public String getExtensionType ()
          {
            return type;
          }
        
        byte[] mac;
        
        public byte[] getMac ()
          {
            return mac;
          }
        
        public abstract byte getSubType ();
        
        public String getQualifier () throws IOException
          {
            return "";
          }
        
        public abstract byte[] getExtensionData () throws IOException;
        
        Extension (DOMReaderHelper rd, IssuedCredential cpk) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            type = ah.getString (TYPE_ATTR);
            mac = ah.getBinary (MAC_ATTR);
            cpk.extensions.add (this);
          }
      }


    class StandardExtension extends Extension
      {
        byte[] data;

        StandardExtension (byte[] data, DOMReaderHelper rd, IssuedCredential cpk) throws IOException
          {
            super (rd, cpk);
            this.data = data;
          }


        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_EXTENSION;
          }


        @Override
        public byte[] getExtensionData () throws IOException
          {
            return data;
          }

      }

    
    class EncryptedExtension extends Extension
      {
        byte[] data;
         
        EncryptedExtension (byte[] data, DOMReaderHelper rd, IssuedCredential cpk) throws IOException
          {
            super (rd, cpk);
            this.data = data;
          }
  
  
        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION;
          }
  
  
        @Override
        public byte[] getExtensionData () throws IOException
          {
            return data;
          }
  
      }


    class Property
      {
        private Property () {}

        String name;

        String value;

        boolean writable;
      }
    

    class PropertyBag extends Extension
      {
        private PropertyBag (DOMReaderHelper rd, IssuedCredential cpk) throws IOException
          {
            super (rd, cpk);
          }

        Vector<Property> properties = new Vector<Property> ();

        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_PROPERTY_BAG;
          }


        private byte[] getStringData (String string) throws IOException
          {
            byte[] data = string.getBytes ("UTF-8");
            return ArrayUtil.add (new byte[]{(byte)(data.length >>> 8), (byte)data.length}, data);
          }

        @Override
        public byte[] getExtensionData () throws IOException
          {
            byte[] total = new byte[0];
            for (Property prop : properties)
              {
                total = ArrayUtil.add (total,
                                       ArrayUtil.add (getStringData (prop.name),
                                                      ArrayUtil.add (new byte[]{prop.writable ? (byte)1 : (byte)0},
                                                                     getStringData (prop.value))));
              }
            return total;
          }
      }


    class Logotype extends Extension
      {
        byte[] data;
        
        String mimeType;
  
        Logotype (byte[] data, String mimeType, DOMReaderHelper rd, IssuedCredential cpk) throws IOException
          {
            super (rd, cpk);
            this.mimeType = mimeType;
            this.data = data;
          }
  
        @Override
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_LOGOTYPE;
          }
  
        @Override
        public String getQualifier ()
          {
            return mimeType;
          }

        @Override
        public byte[] getExtensionData () throws IOException
          {
            return data;
          }
      }


    public class IssuedCredential
      {
        X509Certificate[] certificatePath;

        String id;

        byte[] encrypted_symmetric_key;

        byte[] symmetric_key_mac;

        byte[] encrypted_private_key;

        byte[] private_key_mac;

        byte[] mac;
        
        boolean trust_anchor;

        Vector<Extension> extensions = new Vector<Extension> ();
        
        PostOperation postOperation;

        IssuedCredential () { }


        IssuedCredential (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            rd.getNext (ISSUED_CREDENTIAL_ELEM);
            id = ah.getString (ID_ATTR);
            mac = ah.getBinary (MAC_ATTR);
            trust_anchor = ah.getBooleanConditional (TRUST_ANCHOR_ATTR);
            rd.getChild ();

            certificatePath = XMLSignatureWrapper.readSortedX509DataSubset (rd);            

            if (trust_anchor)
              {
                if (certificatePath[certificatePath.length - 1].getBasicConstraints () < 0)
                  {
                    throw new IOException ("The \"TrustAnchor\" option requires a CA certificate");
                  }
              }

            if (rd.hasNext (IMPORT_KEY_ELEM))
              {
                rd.getNext ();
                rd.getChild ();
                if (rd.hasNext (SYMMETRIC_KEY_ELEM))
                  {
                    encrypted_symmetric_key = rd.getBinary (SYMMETRIC_KEY_ELEM);
                    rd.getParent ();
                    symmetric_key_mac = ah.getBinary (MAC_ATTR);
                  }
                else if (rd.hasNext (PRIVATE_KEY_ELEM))
                  {
                    encrypted_private_key = rd.getBinary (PRIVATE_KEY_ELEM);
                    rd.getParent ();
                    private_key_mac = ah.getBinary (MAC_ATTR);
                  }
              }

            while (rd.hasNext ())
              {
                if (rd.hasNext (PROPERTY_BAG_ELEM))
                  {
                    rd.getNext (PROPERTY_BAG_ELEM);
                    PropertyBag propertyBag = new PropertyBag (rd, this);
                    rd.getChild ();
                    while (rd.hasNext (PROPERTY_ELEM))
                      {
                        rd.getNext (PROPERTY_ELEM);
                        Property property = new Property ();
                        property.name = ah.getString (NAME_ATTR);
                        property.value = ah.getString (VALUE_ATTR);
                        property.writable = ah.getBooleanConditional (WRITABLE_ATTR);
                        propertyBag.properties.add (property);
                      }
                    rd.getParent ();
                  }
                else if (rd.hasNext (LOGOTYPE_ELEM))
                  {
                    new Logotype (rd.getBinary (LOGOTYPE_ELEM), ah.getString (MIME_TYPE_ATTR), rd, this);
                  }
                else if (rd.hasNext (EXTENSION_ELEM))
                  {
                    new StandardExtension (rd.getBinary (EXTENSION_ELEM), rd, this);
                  }
                else if (rd.hasNext (ENCRYPTED_EXTENSION_ELEM))
                  {
                    new EncryptedExtension (rd.getBinary (ENCRYPTED_EXTENSION_ELEM), rd, this);
                  }
                else if (rd.hasNext (CLONE_KEY_PROTECTION_ELEM))
                  {
                    postOperation = readPostOperation (rd, PostOperation.CLONE_KEY_PROTECTION, CLONE_KEY_PROTECTION_ELEM);
                  }
                else
                  {
                    postOperation = readPostOperation (rd, PostOperation.UPDATE_KEY, UPDATE_KEY_ELEM);
                  }
              }
            rd.getParent ();
          }


        public X509Certificate[] getCertificatePath ()
          {
            return certificatePath;
          }


        public byte[] getEncryptedSymmetricKey ()
          {
            return encrypted_symmetric_key;
          }


        public byte[] getSymmetricKeyMac ()
          {
            return symmetric_key_mac;
          }


        public byte[] getEncryptedPrivateKey ()
          {
            return encrypted_private_key;
          }


        public byte[] getPrivateKeyMac ()
          {
            return private_key_mac;
          }


        public String getID ()
          {
            return id;
          }

        public byte[] getMac ()
          {
            return mac;
          }


        public Extension[] getExtensions ()
          {
            return extensions.toArray (new Extension[0]);
          }
        
        public PostOperation getPostOperation ()
          {
            return postOperation;
          }

        public boolean getTrustAnchorFlag ()
          {
            return trust_anchor;
          }

      }
    
    private PostOperation readPostOperation (DOMReaderHelper rd, int post_op, String xml_elem) throws IOException
      {
        rd.getNext (xml_elem);
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        return new PostOperation (ah.getString (CLIENT_SESSION_ID_ATTR),
                                  ah.getString (SERVER_SESSION_ID_ATTR),
                                  ah.getBinary (CertificateFilter.CF_FINGER_PRINT),
                                  ah.getBinary (AUTHORIZATION_ATTR),
                                  ah.getBinary (MAC_ATTR),
                                  post_op);
      }

    private Vector<IssuedCredential> issued_keys = new Vector<IssuedCredential> ();
    
    private Vector<PostOperation> post_unlock_keys = new Vector<PostOperation> ();
      
    private Vector<PostOperation> post_delete_keys = new Vector<PostOperation> ();
    
    private String clientSessionId;

    private String serverSessionId;

    private String submitUrl;

    private XMLSignatureWrapper signature;                  // Optional

    private byte[] close_session_mac;
    
    private byte[] close_session_nonce;


    public String getServerSessionId ()
      {
        return serverSessionId;
      }


    public String getClientSessionId ()
      {
        return clientSessionId;
      }


    public String getSubmitUrl ()
      {
        return submitUrl;
      }


    public IssuedCredential[] getIssuedKeys ()
      {
        return issued_keys.toArray (new IssuedCredential[0]);
      }
    
    
    public PostOperation[] getPostUnlockKeys ()
      {
        return post_unlock_keys.toArray (new PostOperation[0]);
      }

    
    public PostOperation[] getPostDeleteKeys ()
      {
        return post_delete_keys.toArray (new PostOperation[0]);
      }


    public byte[] getCloseSessionMAC ()
      {
        return close_session_mac;
      }

    
    public byte[] getCloseSessionNonce ()
      {
        return close_session_nonce;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, serverSessionId);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        clientSessionId = ah.getString (CLIENT_SESSION_ID_ATTR);

        serverSessionId = ah.getString (ID_ATTR);

        submitUrl = ah.getString (SUBMIT_URL_ATTR);
        
        close_session_mac = ah.getBinary (MAC_ATTR);
        
        close_session_nonce = ah.getBinary (CHALLENGE_ATTR);

        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the issued_keys [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext (ISSUED_CREDENTIAL_ELEM))
          {
            issued_keys.add (new IssuedCredential (rd));
          }
 
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional post provisioning unlocks
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext (UNLOCK_KEY_ELEM))
          {
            post_unlock_keys.add (readPostOperation (rd, PostOperation.UNLOCK_KEY, UNLOCK_KEY_ELEM));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional post provisioning deletes
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext (DELETE_KEY_ELEM))
          {
            post_delete_keys.add (readPostOperation (rd, PostOperation.DELETE_KEY, DELETE_KEY_ELEM));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ())// Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }

  }
