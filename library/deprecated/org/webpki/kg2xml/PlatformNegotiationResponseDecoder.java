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

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class PlatformNegotiationResponseDecoder extends PlatformNegotiationResponse
  {
    Vector<ImagePreference> image_preferences = new Vector<ImagePreference> ();

    BasicCapabilities basic_capabilities = new BasicCapabilities (true);

    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }

    public String getServerSessionId ()
      {
        return serverSessionId;
      }


    public ImagePreference[] getImagesPreferences ()
      {
        return image_preferences.toArray (new ImagePreference[0]);
      }

    
    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes
        //////////////////////////////////////////////////////////////////////////
        serverSessionId = ah.getString (SERVER_SESSION_ID_ATTR);
        
        nonce = ah.getBinaryConditional (NONCE_ATTR);

        BasicCapabilities.read (ah, basic_capabilities, false);
        
        //////////////////////////////////////////////////////////////////////////
        // Get the child elements
        //////////////////////////////////////////////////////////////////////////
        rd.getChild ();

        while (rd.hasNext (IMAGE_PREFERENCE_ELEM))
          {
            ImagePreference im_pref = new ImagePreference ();
            rd.getNext (IMAGE_PREFERENCE_ELEM);
            im_pref.type = ah.getString (TYPE_ATTR);
            im_pref.mimeType = ah.getString (MIME_TYPE_ATTR);
            im_pref.width = ah.getInt (WIDTH_ATTR);
            im_pref.height = ah.getInt (HEIGHT_ATTR);
            image_preferences.add (im_pref);
          }
      }
  }
