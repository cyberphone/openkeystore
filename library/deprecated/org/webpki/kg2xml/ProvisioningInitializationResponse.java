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

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.kg2xml.KeyGen2Constants.*;


abstract class ProvisioningInitializationResponse extends XMLObjectWrapper
  {
    ProvisioningInitializationResponse () {}

    String serverSessionId;
    
    String clientSessionId;

    Date serverTime;
    
    Date clientTime;
    
    ECPublicKey client_ephemeral_key;
    
    HashMap<String,HashSet<String>> client_attribute_values = new HashMap<String,HashSet<String>> ();

    byte[] attestation;
    
    X509Certificate[] device_certificate_path;  // Is null for the privacy_enabled mode
    
    byte[] server_certificate_fingerprint;  // Optional


    void addClientAttribute (String type, String value)
      {
        HashSet<String> set = client_attribute_values.get (type);
        if (set == null)
          {
            client_attribute_values.put (type, set = new HashSet<String> ());
          }
        set.add (value);
      }


    /**
     * Internal Use Only
     */
    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema (KEYGEN2_SCHEMA_FILE);
      }


    /**
     * Internal Use Only
     */
    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    /**
     * Internal Use Only
     */
    public String namespace ()
      {
        return KEYGEN2_NS;
      }

    
    /**
     * Internal Use Only
     */
    public String element ()
      {
        return PROVISIONING_INITIALIZATION_RESPONSE_ELEM;
      }


    /**
     * Internal Use Only
     */
    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }


    /**
     * Internal Use Only
     */
    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }

  }
