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

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.kg2xml.KeyGen2Constants.*;


abstract class KeyCreationRequest extends XMLObjectWrapper
  {
    KeyCreationRequest () {}


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
        return KEY_CREATION_REQUEST_ELEM;
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
