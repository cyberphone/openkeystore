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
import java.util.HashMap;
import java.util.HashSet;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.kg2xml.KeyGen2Constants.*;


public class ProvisioningInitializationResponseDecoder extends ProvisioningInitializationResponse
  {
    XMLSignatureWrapper signature;


    public String getServerSessionId ()
      {
        return serverSessionId;
      }

    
    public String getClientSessionId ()
      {
        return clientSessionId;
      }


    public Date getServerTime ()
      {
        return serverTime;
      }

    
    public Date getClientTime ()
      {
        return clientTime;
      }

    
    public ECPublicKey getClientEphemeralKey ()
      {
        return client_ephemeral_key;
      }


    public byte[] getAttestation ()
      {
        return attestation;
      }


    public X509Certificate[] getDeviceCertificatePath ()
      {
        return device_certificate_path;
      }
    

    public byte[] getServerCertificateFingerprint ()
      {
        return server_certificate_fingerprint;
      }


    public HashMap<String,HashSet<String>> getClientAttributeValues ()
      {
        return client_attribute_values;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////
        clientSessionId = ah.getString (ID_ATTR);

        serverSessionId = ah.getString (SERVER_SESSION_ID_ATTR);

        serverTime = ah.getDateTime (SERVER_TIME_ATTR).getTime ();

        clientTime = ah.getDateTime (CLIENT_TIME_ATTR).getTime ();

        attestation = ah.getBinary (SESSION_ATTESTATION_ATTR);
        
        server_certificate_fingerprint = ah.getBinaryConditional (SERVER_CERT_FP_ATTR);
        
        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the ephemeral client key
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (CLIENT_EPHEMERAL_KEY_ELEM);
        rd.getChild ();
        client_ephemeral_key = (ECPublicKey) XMLSignatureWrapper.readPublicKey (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional device certificate path
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (DEVICE_CERTIFICATE_ELEM))
          {
            rd.getNext (DEVICE_CERTIFICATE_ELEM);
            rd.getChild ();
            device_certificate_path = XMLSignatureWrapper.readSortedX509DataSubset (rd);
            rd.getParent ();
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional client attributes
        /////////////////////////////////////////////////////////////////////////////////////////
        while (rd.hasNext (CLIENT_ATTRIBUTE_ELEM))
          {
            rd.getNext ();
            addClientAttribute (ah.getString (TYPE_ATTR), ah.getString (VALUE_ATTR));
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the mandatory provisioning session data signature
        /////////////////////////////////////////////////////////////////////////////////////////
        signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
      }
  }
