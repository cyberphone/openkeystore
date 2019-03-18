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

import java.util.LinkedHashMap;

import java.security.PublicKey;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class KeyCreationResponseDecoder extends KeyCreationResponse
  {
    LinkedHashMap<String,GeneratedPublicKey> generatedKeys = new LinkedHashMap<String,GeneratedPublicKey> ();

    class GeneratedPublicKey
      {
        private GeneratedPublicKey () {}

        String id;

        PublicKey publicKey;

        byte[] attestation;
      }


    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes
        //////////////////////////////////////////////////////////////////////////
        clientSessionId = ah.getString (ID_ATTR);

        serverSessionId = ah.getString (SERVER_SESSION_ID_ATTR);

        rd.getChild ();

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        do
          {
            GeneratedPublicKey gk = new GeneratedPublicKey ();
            rd.getNext (GENERATED_KEY_ELEM);
            gk.id = ah.getString (ID_ATTR);
            gk.attestation = ah.getBinary (KEY_ATTESTATION_ATTR);
            rd.getChild ();
            gk.publicKey = XMLSignatureWrapper.readPublicKey (rd);
            rd.getParent ();
            if (generatedKeys.put (gk.id, gk) != null)
              {
                ServerState.bad ("Duplicate key id:" + gk.id);
              }
          }
        while (rd.hasNext (GENERATED_KEY_ELEM));
      }
  }
