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


public enum ClaimType
  {
    PPID                ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier", "PPID"),
    GIVEN_NAME          ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",                 "Given Name"),
    SUR_NAME            ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",                   "Surname"),
    EMAIL_ADDRESS       ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",              "Email"),
    STREET_ADDRESS      ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress",             "Street"),
    LOCALITY            ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality",                  "City"),
    STATE_OR_PROVINCE   ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince",           "State"),
    POSTAL_CODE         ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode",                "Postalcode"),
    COUNTRY             ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country",                   "Country"),
    HOME_PHONE          ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone",                 "Telephone"),
    DATE_OF_BIRTH       ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth",               "Date of Birth"),
    GENDER              ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender",                    "Gender");

    private final String xml_name;       // As expressed in XML

    private final String display_tag;    // As expressed in XML

    private ClaimType (String xml_name, String display_tag)
      {
        this.xml_name = xml_name;
        this.display_tag = display_tag;
      }


    public String getXMLName ()
      {
        return xml_name;
      }


    public String getDisplayTag ()
      {
        return display_tag;
      }


    public static ClaimType getClaimTypeFromString (String xml_name) throws IOException
      {
        for (ClaimType ct : ClaimType.values ())
          {
            if (xml_name.equals (ct.xml_name))
              {
                return ct;
              }
          }
        throw new IOException ("Unknown claim type: " + xml_name);
      }

  }
