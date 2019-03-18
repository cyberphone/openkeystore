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

import org.w3c.dom.Document;

import org.webpki.sks.SecureKeyStore;
import org.webpki.util.Base64URL;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;
import org.webpki.kg2xml.ServerState.ProtocolPhase;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class PlatformNegotiationRequestEncoder extends PlatformNegotiationRequest
  {
    private String prefix;  // Default: no prefix
    
    Action action = Action.MANAGE;

    boolean needs_dsig_ns;

    private ServerState serverState;

    // Constructors

    public PlatformNegotiationRequestEncoder (ServerState serverState,
                                              String submitUrl,
                                              String serverSessionId) throws IOException
      {
        serverState.checkState (true, ProtocolPhase.PLATFORM_NEGOTIATION);
        this.serverState = serverState;
        this.submitUrl = submitUrl;
        if (serverSessionId == null)
          {
            serverSessionId = Long.toHexString (new Date().getTime());
            serverSessionId += Base64URL.generateURLFriendlyRandom (SecureKeyStore.MAX_LENGTH_ID_TYPE - serverSessionId.length ());
          }
        this.serverSessionId = serverState.serverSessionId = serverSessionId;
      }
    
    public BasicCapabilities getBasicCapabilities ()
      {
        return serverState.basic_capabilities;
      }
   
    public void setAction (Action action)
      {
        this.action = action;
      }

    public void setAbortURL (String abortUrl)
      {
        this.abortUrl = abortUrl;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        needs_dsig_ns = true;
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, serverSessionId);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ACTION_ATTR, action.getXMLName ());

        wr.setStringAttribute (ID_ATTR, serverSessionId);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submitUrl);
        
        if (abortUrl != null)
          {
            wr.setStringAttribute (ABORT_URL_ATTR, abortUrl);
          }
        
        ////////////////////////////////////////////////////////////////////////
        // Basic capabilities
        ////////////////////////////////////////////////////////////////////////
        BasicCapabilities.write (wr, serverState.basic_capabilities, true);

        if (serverState.privacy_enabled_set)
          {
            wr.setBooleanAttribute (PRIVACY_ENABLED_ATTR, serverState.privacy_enabled);
          }
        
        if (needs_dsig_ns) XMLSignatureWrapper.addXMLSignatureNS (wr);
      }
  }
