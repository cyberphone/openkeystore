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
import java.util.Vector;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.kg2xml.KeyGen2Constants.*;


public class ProvisioningInitializationRequestDecoder extends ProvisioningInitializationRequest
  {
    public class KeyManagementKeyUpdateHolder
      {
        Vector<KeyManagementKeyUpdateHolder> children = new Vector<KeyManagementKeyUpdateHolder> ();
        
        PublicKey kmk;

        byte[] authorization;
        
        public KeyManagementKeyUpdateHolder[] KeyManagementKeyUpdateHolders ()
          {
            return children.toArray (new KeyManagementKeyUpdateHolder[0]);
          }
        
        public PublicKey getKeyManagementKey ()
          {
            return kmk;
          }
        
        KeyManagementKeyUpdateHolder (PublicKey kmk)
          {
            this.kmk = kmk;
          }

        public byte[] getAuthorization ()
          {
            return authorization;
          }
      }
    
    private KeyManagementKeyUpdateHolder kmk_root = new KeyManagementKeyUpdateHolder (null);
    
    public KeyManagementKeyUpdateHolder getKeyManagementKeyUpdateHolderRoot ()
      {
        return kmk_root;
      }

    private XMLSignatureWrapper signature;  // Optional

    String session_key_algorithm;
    
    public String getServerSessionId ()
      {
        return serverSessionId;
      }


    public Date getServerTime ()
      {
        return serverTime;
      }


    public String getSubmitUrl ()
      {
        return submitUrl;
      }

    
    public ECPublicKey getServerEphemeralKey ()
      {
        return server_ephemeral_key;
      }

    
    public String getSessionKeyAlgorithm ()
      {
        return session_key_algorithm;
      }


    public int getSessionLifeTime ()
      {
        return sessionLifeTime;
      }

    
    public short getSessionKeyLimit ()
      {
        return sessionKeyLimit;
      }


    PublicKey keyManagementKey;

    public PublicKey getKeyManagementKey ()
      {
        return keyManagementKey;
      }

    
    public String getVirtualMachineFriendlyName ()
      {
        return virtual_machine_friendly_name;
      }


    public String[] getClientAttributes ()
      {
        return client_attributes.toArray (new String[0]);
      }
 
    
    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, serverSessionId);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    private void scanForUpdateKeys (DOMReaderHelper rd, KeyManagementKeyUpdateHolder kmk) throws IOException
      {
        while (rd.hasNext (UPDATABLE_KEY_MANAGEMENT_KEY_ELEM))
          {
            rd.getNext ();
            byte[] authorization = rd.getAttributeHelper ().getBinary (AUTHORIZATION_ATTR);
            rd.getChild ();
            KeyManagementKeyUpdateHolder child = new KeyManagementKeyUpdateHolder (XMLSignatureWrapper.readPublicKey (rd));
            child.authorization = authorization;
            kmk.children.add (child);
            scanForUpdateKeys (rd, child);
            rd.getParent ();
          }
      }

    
    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        serverSessionId = ah.getString (ID_ATTR);

        serverTime = ah.getDateTime (SERVER_TIME_ATTR).getTime ();

        submitUrl = ah.getString (SUBMIT_URL_ATTR);
        
        session_key_algorithm = ah.getString (SESSION_KEY_ALGORITHM_ATTR);
        
        sessionKeyLimit = (short)ah.getInt (SESSION_KEY_LIMIT_ATTR);
        
        sessionLifeTime = ah.getInt (SESSION_LIFE_TIME_ATTR);
        
        String[] attrs = ah.getListConditional (REQUESTED_CLIENT_ATTRIBUTES_ATTR);
        if (attrs != null)
          {
            for (String attr : attrs)
              {
                client_attributes.add (attr);
              }
          }
        
        rd.getChild ();


        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the server key
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (SERVER_EPHEMERAL_KEY_ELEM);
        rd.getChild ();
        server_ephemeral_key = (ECPublicKey) XMLSignatureWrapper.readPublicKey (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional key management key
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (KEY_MANAGEMENT_KEY_ELEM))
          {
            rd.getNext (KEY_MANAGEMENT_KEY_ELEM);
            rd.getChild ();
            scanForUpdateKeys (rd, kmk_root = new KeyManagementKeyUpdateHolder (keyManagementKey = XMLSignatureWrapper.readPublicKey (rd)));
            rd.getParent ();
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional virtual machine
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (VIRTUAL_MACHINE_ELEM))
          {
            virtual_machine_data = rd.getBinary (VIRTUAL_MACHINE_ELEM);
            virtual_machine_type = ah.getString (TYPE_ATTR);
            virtual_machine_friendly_name = ah.getString (FRIENDLY_NAME_ATTR);
            if (!rd.hasNext ())
              {
                throw new IOException ("Virtual Machine requests must be signed");
              }
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ()) // Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }
  }

