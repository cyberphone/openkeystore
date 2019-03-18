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

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;

import java.security.interfaces.RSAPublicKey;

import java.util.Date;
import java.util.Vector;

import org.w3c.dom.Document;

import org.webpki.sks.SecureKeyStore;
import org.webpki.util.ArrayUtil;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSigner;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.SignerInterface;
import org.webpki.kg2xml.ServerState.ProtocolPhase;

import static org.webpki.kg2xml.KeyGen2Constants.*;


public class ProvisioningInitializationRequestEncoder extends ProvisioningInitializationRequest
  {
    String prefix;  // Default: no prefix
    
    ServerState serverState;
    
    KeyManagementKeyUpdateHolder kmk_root;
    
    boolean output_dsig_ns;

    public class KeyManagementKeyUpdateHolder
      {
        PublicKey keyManagementKey;
        
        byte[] authorization;
        
        Vector<KeyManagementKeyUpdateHolder> children = new Vector<KeyManagementKeyUpdateHolder> ();
        
        KeyManagementKeyUpdateHolder (PublicKey keyManagementKey)
          {
            if (keyManagementKey instanceof RSAPublicKey)
              {
                output_dsig_ns = true;
              }
            this.keyManagementKey = keyManagementKey;
          }

        public KeyManagementKeyUpdateHolder update (PublicKey keyManagementKey) throws IOException
          {
            KeyManagementKeyUpdateHolder kmk = new KeyManagementKeyUpdateHolder (keyManagementKey);
            kmk.authorization = serverState.serverCryptoInterface.generateKeyManagementAuthorization (keyManagementKey,
                                                                                                         ArrayUtil.add (SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION,
                                                                                                         this.keyManagementKey.getEncoded ()));
            children.add (kmk);
            return kmk;
          }

        public KeyManagementKeyUpdateHolder update (PublicKey keyManagementKey, byte[] external_authorization) throws IOException
          {
            KeyManagementKeyUpdateHolder kmk = new KeyManagementKeyUpdateHolder (keyManagementKey);
            kmk.authorization = external_authorization;
            try
              {
                Signature kmk_verify = Signature.getInstance (keyManagementKey instanceof RSAPublicKey ? 
                                                                                         "SHA256WithRSA" : "SHA256WithECDSA");
                kmk_verify.initVerify (keyManagementKey);
                kmk_verify.update (SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION);
                kmk_verify.update (this.keyManagementKey.getEncoded ());
                if (!kmk_verify.verify (external_authorization))
                  {
                    throw new IOException ("Authorization signature did not validate");
                  }
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
            children.add (kmk);
            return kmk;
          }
      }    

    // Constructors

    public ProvisioningInitializationRequestEncoder (ServerState serverState,
                                                     String submitUrl,
                                                     int sessionLifeTime,
                                                     short sessionKeyLimit)  throws IOException
      {
        serverState.checkState (true, ProtocolPhase.PROVISIONING_INITIALIZATION);
        this.serverState = serverState;
        super.submitUrl = serverState.issuer_uri = submitUrl;
        super.sessionLifeTime = serverState.sessionLifeTime = sessionLifeTime;
        super.sessionKeyLimit = serverState.sessionKeyLimit = sessionKeyLimit;
        super.nonce = serverState.vm_nonce;
        serverSessionId = serverState.serverSessionId;
        server_ephemeral_key = serverState.server_ephemeral_key = serverState.generateEphemeralKey ();
        for (String client_attribute : serverState.basic_capabilities.client_attributes)
          {
            client_attributes.add (client_attribute);
          }
      }


    public KeyManagementKeyUpdateHolder setKeyManagementKey (PublicKey keyManagementKey)
      {
        return kmk_root = new KeyManagementKeyUpdateHolder (serverState.keyManagementKey = keyManagementKey);
      }


    public void setVirtualMachine (byte[] vm_data, String type, String friendlyName)
      {
        virtual_machine_data = vm_data;
        virtual_machine_type = type;
        virtual_machine_friendly_name = friendlyName;
      }


    public void setSessionKeyAlgorithm (String session_key_algorithm)
      {
        serverState.provisioning_session_algorithm = session_key_algorithm;
      }

    
    public void setServerTime (Date serverTime)
      {
        super.serverTime = serverTime;
      }
    
    
    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        output_dsig_ns = true;
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, serverSessionId);
      }


    private void scanForUpdatedKeys (DOMWriterHelper wr, KeyManagementKeyUpdateHolder kmk) throws IOException
      {
        for (KeyManagementKeyUpdateHolder child : kmk.children)
          {
            wr.addChildElement (UPDATABLE_KEY_MANAGEMENT_KEY_ELEM);
            wr.setBinaryAttribute (AUTHORIZATION_ATTR, child.authorization);
            XMLSignatureWrapper.writePublicKey (wr, child.keyManagementKey);
            scanForUpdatedKeys (wr, child);
            wr.getParent ();
          }
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignature11NS (wr);
        
        if (output_dsig_ns)
          {
            XMLSignatureWrapper.addXMLSignatureNS (wr);
          }

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, serverSessionId);
        
        if (nonce != null)
          {
            wr.setBinaryAttribute (NONCE_ATTR, nonce);
          }

        if (serverTime == null)
          {
            serverTime = new Date ();
          }

        wr.setDateTimeAttribute (SERVER_TIME_ATTR, serverTime);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submitUrl);
        
        wr.setIntAttribute (SESSION_LIFE_TIME_ATTR, sessionLifeTime);

        wr.setIntAttribute (SESSION_KEY_LIMIT_ATTR, sessionKeyLimit);

        wr.setStringAttribute (SESSION_KEY_ALGORITHM_ATTR, serverState.provisioning_session_algorithm);
        
        if (!client_attributes.isEmpty ())
          {
            wr.setListAttribute (REQUESTED_CLIENT_ATTRIBUTES_ATTR, client_attributes.toArray (new String[0]));
          }
        
        ////////////////////////////////////////////////////////////////////////
        // Server ephemeral key
        ////////////////////////////////////////////////////////////////////////
        wr.addChildElement (SERVER_EPHEMERAL_KEY_ELEM);
        XMLSignatureWrapper.writePublicKey (wr, server_ephemeral_key);
        wr.getParent();

        ////////////////////////////////////////////////////////////////////////
        // Key management key
        ////////////////////////////////////////////////////////////////////////
        if (kmk_root != null)
          {
            wr.addChildElement (KEY_MANAGEMENT_KEY_ELEM);
            XMLSignatureWrapper.writePublicKey (wr, kmk_root.keyManagementKey);
            scanForUpdatedKeys (wr, kmk_root);
            wr.getParent();
          }

        ////////////////////////////////////////////////////////////////////////
        // We request a VM as well
        ////////////////////////////////////////////////////////////////////////
        if (virtual_machine_data != null)
          {
            wr.addBinary (VIRTUAL_MACHINE_ELEM, virtual_machine_data);
            wr.setStringAttribute (TYPE_ATTR, virtual_machine_type);
            wr.setStringAttribute (FRIENDLY_NAME_ATTR, virtual_machine_friendly_name);
          }
      }
  }
