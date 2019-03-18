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

import java.util.Date;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.w3c.dom.Document;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSymKeySigner;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import static org.webpki.kg2xml.KeyGen2Constants.*;


public class ProvisioningInitializationResponseEncoder extends ProvisioningInitializationResponse
  {

    String prefix;  // Default: no prefix
    
     // Constructors

    public ProvisioningInitializationResponseEncoder (ECPublicKey client_ephemeral_key,
                                                      String serverSessionId,
                                                      String clientSessionId,
                                                      Date serverTime,
                                                      Date clientTime,
                                                      byte[] attestation,
                                                      X509Certificate[] device_certificate_path)  throws IOException
      {
        super.client_ephemeral_key = client_ephemeral_key;
        super.serverSessionId = serverSessionId;
        super.clientSessionId = clientSessionId;
        super.serverTime = serverTime;
        super.clientTime = clientTime;
        super.attestation = attestation;
        super.device_certificate_path = device_certificate_path;
      }


    public void setServerCertificate (X509Certificate server_certificate) throws IOException
      {
        try
          {
            server_certificate_fingerprint = HashAlgorithms.SHA256.digest (server_certificate.getEncoded ());
          }
        catch (GeneralSecurityException gse)
          {
            throw new IOException (gse);
          }
      }


    public ProvisioningInitializationResponseEncoder setClientAttributeValue (String type, String value)
      {
        addClientAttribute (type, value);
        return this;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SymKeySignerInterface signer) throws IOException
      {
        XMLSymKeySigner ds = new XMLSymKeySigner (signer);
        ds.SetKeyName ("derived-session-key");
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, clientSessionId);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignature11NS (wr);
        XMLSignatureWrapper.addXMLSignatureNS (wr);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, clientSessionId);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, serverSessionId);

        wr.setDateTimeAttribute (SERVER_TIME_ATTR, serverTime);

        wr.setDateTimeAttribute (CLIENT_TIME_ATTR, clientTime);
        
        wr.setBinaryAttribute (SESSION_ATTESTATION_ATTR, attestation);
        
        if (server_certificate_fingerprint != null)
          {
            wr.setBinaryAttribute (SERVER_CERT_FP_ATTR, server_certificate_fingerprint);
          }

        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.addChildElement (CLIENT_EPHEMERAL_KEY_ELEM);
        XMLSignatureWrapper.writePublicKey (wr, client_ephemeral_key);
        wr.getParent();

        ////////////////////////////////////////////////////////////////////////
        // Device certificate path
        ////////////////////////////////////////////////////////////////////////
        if (device_certificate_path != null)
          {
            wr.addChildElement (DEVICE_CERTIFICATE_ELEM);
            XMLSignatureWrapper.writeX509DataSubset (wr, device_certificate_path);
            wr.getParent();
          }
        
        ////////////////////////////////////////////////////////////////////////
        // Optional ClientAttributes
        ////////////////////////////////////////////////////////////////////////
        for (String type : client_attribute_values.keySet ())
          {
            for (String value : client_attribute_values.get (type))
              {
                wr.addChildElement (CLIENT_ATTRIBUTE_ELEM);
                wr.setStringAttribute (TYPE_ATTR, type);
                wr.setStringAttribute (VALUE_ATTR, value);
                wr.getParent();
              }
          }
      }
  }
