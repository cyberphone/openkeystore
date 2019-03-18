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

public enum Action
  {
    MANAGE       ("manage", true, true,  true),
    UNLOCK       ("unlock", true,  false, true),
    RESUME       ("resume", false,  false, false);
  
    private final String xml_name;               // As expressed in XML
    
    private final boolean prov_init_required;    // ProvisioningInitialization required else illegal
  
    private final boolean lookup_allowed;        // CredentialDiscovery permitted
  
    private final boolean key_init_allowed;      // KeyInitialization permitted
  
    private Action (String xml_name, boolean lookup_allowed, boolean key_init_allowed, boolean prov_init_required)
      {
        this.xml_name = xml_name;
        this.lookup_allowed = lookup_allowed;
        this.key_init_allowed = key_init_allowed;
        this.prov_init_required = prov_init_required;
      }
  
  
    public String getXMLName ()
      {
        return xml_name;
      }
    
  
    public boolean mayLookupCredentials ()
      {
        return lookup_allowed;
      }
  
  
    public boolean mayInitializeKeys ()
      {
        return key_init_allowed;
      }
  
    public boolean mustOrMustNotCreateSession ()
      {
        return prov_init_required;
      }
  
  
    public static Action getActionFromString (String xml_name) throws IOException
      {
        for (Action action : Action.values ())
          {
            if (xml_name.equals (action.xml_name))
              {
                return action;
              }
          }
        throw new IOException ("Unknown action: " + xml_name);
      }
  }
