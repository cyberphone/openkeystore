/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

public interface KeyGen2URIs {

    public interface LOGOTYPES {

        String ICON                        = "https://webpki.github.io/keygen2/logotype#icon";

        String CARD                        = "https://webpki.github.io/keygen2/logotype#card";

        String LIST                        = "https://webpki.github.io/keygen2/logotype#list";

        String APPLICATION                 = "https://webpki.github.io/keygen2/logotype#application";
    }

    // Values
    public interface CLIENT_ATTRIBUTES {

        String IMEI_NUMBER                 = "https://webpki.github.io/keygen2/clientattr#imei-number";
        
        String MAC_ADDRESS                 = "https://webpki.github.io/keygen2/clientattr#mac-address";
  
        String IP_ADDRESS                  = "https://webpki.github.io/keygen2/clientattr#ip-address";

        String OS_VENDOR                   = "https://webpki.github.io/keygen2/clientattr#os-vendor";

        String OS_VERSION                  = "https://webpki.github.io/keygen2/clientattr#os-version";
    }

    // True/False
    public interface CLIENT_FEATURES {

        String DEVICE_PIN_SUPPORT          = "https://webpki.github.io/keygen2/feature#device-pin-support";

        String BIOMETRIC_SUPPORT           = "https://webpki.github.io/keygen2/feature#biometric-support";
    }
}
