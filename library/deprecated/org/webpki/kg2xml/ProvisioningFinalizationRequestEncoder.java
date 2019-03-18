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


import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;

import org.webpki.kg2xml.ServerState.PostProvisioningTargetKey;
import org.webpki.kg2xml.ServerState.ProtocolPhase;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class ProvisioningFinalizationRequestEncoder extends ProvisioningFinalizationRequest
  {
    String submitUrl;

    private String prefix;  // Default: no prefix

    ServerState serverState;
    
   
    // Constructors

    public ProvisioningFinalizationRequestEncoder (ServerState serverState, String submitUrl) throws IOException
      {
        this.serverState = serverState;
        this.submitUrl = submitUrl;
        serverState.checkState (true, serverState.current_phase == ProtocolPhase.KEY_CREATION? ProtocolPhase.KEY_CREATION : ProtocolPhase.PROVISIONING_FINALIZATION);
        serverState.current_phase = ProtocolPhase.PROVISIONING_FINALIZATION;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, serverState.serverSessionId);
      }
    
    
    private byte[] mac (byte[] data, byte[] method) throws IOException, GeneralSecurityException
      {
        return serverState.mac (data, method);
      }
    
    
    private void mac (DOMWriterHelper wr, byte[] data, byte[] method) throws IOException, GeneralSecurityException
      {
        wr.setBinaryAttribute (MAC_ATTR, mac (data, method));
      }
    
    
    private void writePostOp (DOMWriterHelper wr,
                              PostProvisioningTargetKey targetKey,
                              MacGenerator post_op_mac) throws IOException, GeneralSecurityException
      {
        wr.addChildElement (targetKey.postOperation.getXMLElem ());
        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, targetKey.clientSessionId);
        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, targetKey.serverSessionId);
        wr.setBinaryAttribute (CertificateFilter.CF_FINGER_PRINT, HashAlgorithms.SHA256.digest (targetKey.certificate_data));
        byte[] deviceId = serverState.device_certificate == null ? SecureKeyStore.KDF_ANONYMOUS : serverState.device_certificate.getEncoded ();
        byte[] keyId = serverState.serverCryptoInterface.mac (targetKey.certificate_data, deviceId);
        byte[] authorization = serverState.serverCryptoInterface.generateKeyManagementAuthorization (targetKey.keyManagementKey,
                                                                                                        ArrayUtil.add (SecureKeyStore.KMK_TARGET_KEY_REFERENCE,
                                                                                                                       keyId));
        wr.setBinaryAttribute (AUTHORIZATION_ATTR, authorization);
        post_op_mac.addArray (authorization);
        mac (wr, post_op_mac.getResult (), targetKey.postOperation.getMethod ());
        wr.getParent ();
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        Element top = wr.initializeRootObject (prefix);

        try
          {
            //////////////////////////////////////////////////////////////////////////
            // Set top-level attributes
            //////////////////////////////////////////////////////////////////////////
            wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, serverState.clientSessionId);
    
            wr.setStringAttribute (ID_ATTR, serverState.serverSessionId);
    
            wr.setStringAttribute (SUBMIT_URL_ATTR, submitUrl);
    
            byte[] nonce;
            wr.setBinaryAttribute (CHALLENGE_ATTR, nonce = serverState.serverCryptoInterface.generateNonce ());
    
            XMLSignatureWrapper.addXMLSignatureNS (wr);
    
            ////////////////////////////////////////////////////////////////////////
            // Write [0..n] Credentials
            ////////////////////////////////////////////////////////////////////////
            for (ServerState.Key key : serverState.getKeys ())
              {
                wr.addChildElement (ISSUED_CREDENTIAL_ELEM);
                wr.setStringAttribute (ID_ATTR, key.id);
                if (key.trust_anchor_set)
                  {
                    wr.setBooleanAttribute (TRUST_ANCHOR_ATTR, key.trust_anchor);
                  }

                ////////////////////////////////////////////////////////////////////////
                // Always: the X509 Certificate(s)
                ////////////////////////////////////////////////////////////////////////
                MacGenerator set_certificate = new MacGenerator ();
                set_certificate.addArray (key.publicKey.getEncoded ());
                set_certificate.addString (key.id);
                X509Certificate[] certificatePath = CertificateUtil.getSortedPath (key.certificatePath);
                if (key.trust_anchor_set && !CertificateUtil.isTrustAnchor (certificatePath[certificatePath.length - 1]))
                  {
                    throw new IOException ("Invalid \"" + TRUST_ANCHOR_ATTR + "\"");
                  }
                for (X509Certificate certificate : certificatePath)
                  {
                    set_certificate.addArray (certificate.getEncoded ());
                  }
                mac (wr, set_certificate.getResult (), SecureKeyStore.METHOD_SET_CERTIFICATE_PATH);
                XMLSignatureWrapper.writeX509DataSubset (wr, certificatePath);
                byte[] ee_cert = certificatePath[0].getEncoded ();
                
                ////////////////////////////////////////////////////////////////////////
                // Optional: "piggybacked" symmetric key
                ////////////////////////////////////////////////////////////////////////
                if (key.encrypted_symmetric_key != null)
                  {
                    wr.addChildElement (IMPORT_KEY_ELEM);
                    MacGenerator set_symkey = new MacGenerator ();
                    set_symkey.addArray (ee_cert);
                    set_symkey.addArray (key.encrypted_symmetric_key);
                    mac (wr, set_symkey.getResult (), SecureKeyStore.METHOD_IMPORT_SYMMETRIC_KEY);
                    wr.addBinary (SYMMETRIC_KEY_ELEM, key.encrypted_symmetric_key);
                    wr.getParent ();
                  }
 
                ////////////////////////////////////////////////////////////////////////
                // Optional: private key
                ////////////////////////////////////////////////////////////////////////
                if (key.encrypted_private_key != null)
                  {
                    wr.addChildElement (IMPORT_KEY_ELEM);
                    MacGenerator restore_privkey = new MacGenerator ();
                    restore_privkey.addArray (ee_cert);
                    restore_privkey.addArray (key.encrypted_private_key);
                    mac (wr, restore_privkey.getResult (), SecureKeyStore.METHOD_IMPORT_PRIVATE_KEY);
                    wr.addBinary (PRIVATE_KEY_ELEM, key.encrypted_private_key);
                    wr.getParent ();
                  }
 
                ////////////////////////////////////////////////////////////////////////
                // Optional: property bags, extensions, and logotypes
                ////////////////////////////////////////////////////////////////////////
                for (ServerState.ExtensionInterface ei : key.extensions.values ())
                  {
                    MacGenerator add_ext = new MacGenerator ();
                    add_ext.addArray (ee_cert);
                    add_ext.addString (ei.type);
                    add_ext.addByte (ei.getSubType ());
                    add_ext.addString (ei.getQualifier ());
                    add_ext.addBlob (ei.getExtensionData ());
                    ei.writeExtension (wr, mac (add_ext.getResult (), SecureKeyStore.METHOD_ADD_EXTENSION));
                  }

                ////////////////////////////////////////////////////////////////////////
                // Optional: post operation associated with the provisioned key
                ////////////////////////////////////////////////////////////////////////
                if (key.clone_or_update_operation != null)
                  {
                    MacGenerator set_post_mac = new MacGenerator ();
                    set_post_mac.addArray (ee_cert);
                    writePostOp (wr, key.clone_or_update_operation, set_post_mac);
                  }
 
                wr.getParent ();
              }
            
            ////////////////////////////////////////////////////////////////////////
            // Optional: post provisioning unlock operations
            ////////////////////////////////////////////////////////////////////////
            for (ServerState.PostProvisioningTargetKey pptk : serverState.post_operations)
              {
                if (pptk.postOperation == ServerState.PostOperation.UNLOCK_KEY)
                  {
                    writePostOp (wr, pptk, new MacGenerator ());
                  }
              }
            
            ////////////////////////////////////////////////////////////////////////
            // Optional: post provisioning delete operations
            ////////////////////////////////////////////////////////////////////////
            for (ServerState.PostProvisioningTargetKey pptk : serverState.post_operations)
              {
                if (pptk.postOperation == ServerState.PostOperation.DELETE_KEY)
                  {
                    writePostOp (wr, pptk, new MacGenerator ());
                  }
              }

            ////////////////////////////////////////////////////////////////////////
            // Done with the crypto, now set the "closeProvisioningSession" MAC
            ////////////////////////////////////////////////////////////////////////
            MacGenerator close = new MacGenerator ();
            close.addString (serverState.clientSessionId);
            close.addString (serverState.serverSessionId);
            close.addString (serverState.issuer_uri);
            close.addArray (serverState.saved_close_nonce = nonce);
            top.setAttribute (MAC_ATTR,
                              new Base64 ().getBase64StringFromBinary (mac (close.getResult (),
                                                                            SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION)));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
  }
