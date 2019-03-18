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

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class PlatformNegotiationRequestDecoder extends PlatformNegotiationRequest
  {
    private XMLSignatureWrapper signature;  // Optional
    
    BasicCapabilities basic_capabilities = new BasicCapabilities (true);
    
    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }

    public String getServerSessionId ()
      {
        return serverSessionId;
      }


    public String getSubmitUrl ()
      {
        return submitUrl;
      }


    public String getAbortURL ()
      {
        return abortUrl;
      }

    Action action;

    public Action getAction ()
      {
        return action;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, serverSessionId);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }

    boolean privacy_enabled;

    public boolean getPrivacyEnabledFlag ()
      {
        return privacy_enabled;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        serverSessionId = ah.getString (ID_ATTR);

        submitUrl = ah.getString (SUBMIT_URL_ATTR);

        abortUrl = ah.getStringConditional (ABORT_URL_ATTR);
        
        action = Action.getActionFromString (ah.getString (ACTION_ATTR));

        privacy_enabled = ah.getBooleanConditional (PRIVACY_ENABLED_ATTR);

        BasicCapabilities.read (ah, basic_capabilities, true);

        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        rd.getChild ();

        if (rd.hasNext ())// Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }
  }
