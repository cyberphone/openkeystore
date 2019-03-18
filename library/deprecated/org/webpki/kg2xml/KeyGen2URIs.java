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

public interface KeyGen2URIs
  {
    public interface LOGOTYPES
      {
        String ICON                        = "http://xmlns.webpki.org/keygen2/logotype#icon";

        String CARD                        = "http://xmlns.webpki.org/keygen2/logotype#card";

        String LIST                        = "http://xmlns.webpki.org/keygen2/logotype#list";

        String APPLICATION                 = "http://xmlns.webpki.org/keygen2/logotype#application";
      }

    public interface CLIENT_ATTRIBUTES
      {
        String IMEI_NUMBER                 = "http://xmlns.webpki.org/keygen2/clientattr#imei-number";
  
        String MAC_ADDRESS                 = "http://xmlns.webpki.org/keygen2/clientattr#mac-address";
  
        String IP_ADDRESS                  = "http://xmlns.webpki.org/keygen2/clientattr#ip-address";

        String OS_VENDOR                   = "http://xmlns.webpki.org/keygen2/clientattr#os-vendor";

        String OS_VERSION                  = "http://xmlns.webpki.org/keygen2/clientattr#os-version";
      }

    public interface FEATURE
      {
        String VIRTUAL_MACHINE             = "http://xmlns.webpki.org/keygen2/feature#vm";
      }
  }
