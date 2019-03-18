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

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.kg2xml.KeyGen2Constants.*;


public class KeyCreationResponseEncoder extends KeyCreationResponse
  {
    private Vector<GeneratedPublicKey> generatedKeys = new Vector<GeneratedPublicKey> ();

    private String prefix;  // Default: no prefix

    private boolean need_ds11_namespace;


    private class GeneratedPublicKey
      {
        String id;

        PublicKey publicKey;

        byte[] key_attestation;

        GeneratedPublicKey (String id)
          {
            this.id = id;
            generatedKeys.add (this);
          }

      }


    public void addPublicKey (PublicKey publicKey, byte[] key_attestation, String id) throws IOException
      {
        GeneratedPublicKey gk = new GeneratedPublicKey (id);
        gk.publicKey = publicKey;
        if (publicKey instanceof ECPublicKey)
          {
            need_ds11_namespace = true;
          }
        gk.key_attestation = key_attestation;
      }


    public void setPrefix (String prefix) throws IOException
      {
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    public KeyCreationResponseEncoder (KeyCreationRequestDecoder key_init_req) throws IOException
      {
        clientSessionId = key_init_req.getClientSessionId ();
        serverSessionId = key_init_req.getServerSessionId ();
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        XMLSignatureWrapper.addXMLSignatureNS (wr);

        if (need_ds11_namespace)
          {
            XMLSignatureWrapper.addXMLSignature11NS (wr);
          }

        wr.setStringAttribute (ID_ATTR, clientSessionId);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, serverSessionId);
      
        for (GeneratedPublicKey gk : generatedKeys)
          {
            wr.addChildElement (GENERATED_KEY_ELEM);
            wr.setStringAttribute (ID_ATTR, gk.id);
            wr.setBinaryAttribute (KEY_ATTESTATION_ATTR, gk.key_attestation);
            XMLSignatureWrapper.writePublicKey (wr, gk.publicKey);
            wr.getParent ();
          }
      }
  }
