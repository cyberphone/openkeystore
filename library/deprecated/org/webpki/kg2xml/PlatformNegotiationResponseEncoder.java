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
import java.io.IOException;

import java.util.Vector;

import org.webpki.xml.DOMWriterHelper;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class PlatformNegotiationResponseEncoder extends PlatformNegotiationResponse
  {
    private String prefix;  // Default: no prefix
    
    Vector<ImagePreference> image_preferences = new Vector<ImagePreference> ();


    public void setPrefix (String prefix) throws IOException
      {
        this.prefix = prefix;
      }


    public String getPrefix ()
      {
        return prefix;
      }


    public PlatformNegotiationResponseEncoder addImagePreference (String type_url,
                                                                  String mimeType,
                                                                  int width,
                                                                  int height)
      {
        ImagePreference im_pref = new ImagePreference ();
        im_pref.type = type_url;
        im_pref.mimeType = mimeType;
        im_pref.width = width;
        im_pref.height = height;
        image_preferences.add (im_pref);
        return this;
      }

    BasicCapabilities basic_capabilities = new BasicCapabilities (false);

    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }

    public PlatformNegotiationResponseEncoder (PlatformNegotiationRequestDecoder decoder)
      {
        this.serverSessionId = decoder.serverSessionId;
      }
    
    public void setNonce (byte[] nonce)
      {
        this.nonce = nonce;
      }

    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, serverSessionId);
        
        ////////////////////////////////////////////////////////////////////////
        // VM mandatory option
        ////////////////////////////////////////////////////////////////////////
        if (nonce != null)
          {
            wr.setBinaryAttribute (NONCE_ATTR, nonce);
          }

        ////////////////////////////////////////////////////////////////////////
        // Basic capabilities
        ////////////////////////////////////////////////////////////////////////
        BasicCapabilities.write (wr, basic_capabilities, false);

        ////////////////////////////////////////////////////////////////////////
        // Optional image preferences
        ////////////////////////////////////////////////////////////////////////
        for (ImagePreference im_pref : image_preferences)
          {
            wr.addChildElement (IMAGE_PREFERENCE_ELEM);
            wr.setStringAttribute (TYPE_ATTR, im_pref.type);
            wr.setStringAttribute (MIME_TYPE_ATTR, im_pref.mimeType);
            wr.setIntAttribute (WIDTH_ATTR, im_pref.width);
            wr.setIntAttribute (HEIGHT_ATTR, im_pref.height);
            wr.getParent ();
          }
      }
  }
