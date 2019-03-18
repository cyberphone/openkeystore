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
package org.webpki.keygen2;

public enum KeyGen2Messages {

    INVOCATION_REQUEST                   ("InvocationRequest"),
    INVOCATION_RESPONSE                  ("InvocationResponse"),
    CREDENTIAL_DISCOVERY_REQUEST         ("CredentialDiscoveryRequest"),
    CREDENTIAL_DISCOVERY_RESPONSE        ("CredentialDiscoveryResponse"),
    KEY_CREATION_REQUEST                 ("KeyCreationRequest"),
    KEY_CREATION_RESPONSE                ("KeyCreationResponse"),
    PROVISIONING_INITIALIZATION_REQUEST  ("ProvisioningInitializationRequest"),
    PROVISIONING_INITIALIZATION_RESPONSE ("ProvisioningInitializationResponse"),
    PROVISIONING_FINALIZATION_REQUEST    ("ProvisioningFinalizationRequest"),
    PROVISIONING_FINALIZATION_RESPONSE   ("ProvisioningFinalizationResponse");

    String name;

    KeyGen2Messages(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
