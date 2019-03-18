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
package org.webpki.infocard;

import java.io.IOException;


public enum TokenType
  {
    SAML_1_0   ("urn:oasis:names:tc:SAML:1.0:assertion"),
    SAML_1_1   ("urn:oasis:names:tc:SAML:1.1:assertion"),
    SAML_2_0   ("urn:oasis:names:tc:SAML:2.0:assertion");

    private final String xml_name;       // As expressed in XML

    private TokenType (String xml_name)
      {
        this.xml_name = xml_name;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public static TokenType getTokenTypeFromString (String xml_name) throws IOException
      {
        for (TokenType tt : TokenType.values ())
          {
            if (xml_name.equals (tt.xml_name))
              {
                return tt;
              }
          }
        throw new IOException ("Unknown token type: " + xml_name);
      }

  }
