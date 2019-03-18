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

import org.webpki.sks.SecureKeyStore;

public interface KeyGen2Constants {

    String KEYGEN2_NS                                = "http://xmlns.webpki.org/keygen2/beta/20170513";

    // JSON properties

    String ACTION_JSON                               = "action";
    
    String APP_USAGE_JSON                            = SecureKeyStore.VAR_APP_USAGE;

    String ATTESTATION_JSON                          = SecureKeyStore.VAR_ATTESTATION;

    String AUTHORIZATION_JSON                        = SecureKeyStore.VAR_AUTHORIZATION;

    String BIOMETRIC_PROTECTION_JSON                 = SecureKeyStore.VAR_BIOMETRIC_PROTECTION;

    String CANCEL_URL_JSON                           = "cancelUrl";

    String CLIENT_CAPABILITIES_JSON                  = "clientCapabilities";

    String CLIENT_CAPABILITY_QUERY_JSON              = "clientCapabilityQuery";

    String CLIENT_EPHEMERAL_KEY_JSON                 = SecureKeyStore.VAR_CLIENT_EPHEMERAL_KEY;

    String CLIENT_SESSION_ID_JSON                    = SecureKeyStore.VAR_CLIENT_SESSION_ID;

    String CLIENT_TIME_JSON                          = SecureKeyStore.VAR_CLIENT_TIME;

    String CLONE_KEY_PROTECTION_JSON                 = "cloneKeyProtection";
    
    String EXTENSION_DATA_JSON                       = SecureKeyStore.VAR_EXTENSION_DATA;
    
    String DEFERRED_ISSUANCE_JSON                    = "deferredIssuance";

    String DELETE_KEYS_JSON                          = "deleteKeys";
    
    String DELETE_PROTECTION_JSON                    = SecureKeyStore.VAR_DELETE_PROTECTION;

    String DEVICE_ID_JSON                            = "deviceId";

    String DEVICE_PIN_PROTECTION_JSON                = SecureKeyStore.VAR_DEVICE_PIN_PROTECTION;

    String ENDORSED_ALGORITHMS_JSON                  = SecureKeyStore.VAR_ENDORSED_ALGORITHMS;

    String ENABLE_PIN_CACHING_JSON                   = SecureKeyStore.VAR_ENABLE_PIN_CACHING;

    String ENCRYPTED_EXTENSIONS_JSON                 = "encryptedExtensions";

    String ENCRYPTED_KEY_JSON                        = SecureKeyStore.VAR_ENCRYPTED_KEY;

    String ENCRYPTED_PIN_JSON                        = "encryptedPin";
    
    String ENCRYPTED_PUK_JSON                        = SecureKeyStore.VAR_ENCRYPTED_PUK;

    String EXPORT_PROTECTION_JSON                    = SecureKeyStore.VAR_EXPORT_PROTECTION;

    String EXTENSIONS_JSON                           = "extensions";

    String FORMAT_JSON                               = SecureKeyStore.VAR_FORMAT;

    String FRIENDLY_NAME_JSON                        = SecureKeyStore.VAR_FRIENDLY_NAME;

    String GENERATED_KEYS_JSON                       = "generatedKeys";

    String GROUPING_JSON                             = SecureKeyStore.VAR_GROUPING;

    String HEIGHT_JSON                               = "height";

    String ID_JSON                                   = SecureKeyStore.VAR_ID;

    String IMAGE_ATTRIBUTES_JSON                     = "imageAttributes";
    
    String IMPORT_PRIVATE_KEY_JSON                   = "importPrivateKey";

    String IMPORT_SYMMETRIC_KEY_JSON                 = "importSymmetricKey";

    String INPUT_METHOD_JSON                         = SecureKeyStore.VAR_INPUT_METHOD;

    String ISSUED_AFTER_JSON                         = "issuedAfter";

    String ISSUED_BEFORE_JSON                        = "issuedBefore";

    String ISSUED_CREDENTIALS_JSON                   = "issuedCredentials";

    String KEY_ALGORITHM_JSON                        = SecureKeyStore.VAR_KEY_ALGORITHM;

    String KEY_ENTRY_ALGORITHM_JSON                  = SecureKeyStore.VAR_KEY_ENTRY_ALGORITHM;       

    String KEY_ENTRY_SPECIFIERS_JSON                 = "keyEntrySpecifiers";       

    String KEY_MANAGEMENT_KEY_JSON                   = SecureKeyStore.VAR_KEY_MANAGEMENT_KEY;

    String KEY_PARAMETERS_JSON                       = SecureKeyStore.VAR_KEY_PARAMETERS;

    String LOCKED_JSON                               = "locked";

    String LOGOTYPES_JSON                            = "logotypes";

    String LOOKUP_RESULTS_JSON                       = "lookupResults";

    String LOOKUP_SPECIFIERS_JSON                    = "lookupSpecifiers";

    String MAC_JSON                                  = SecureKeyStore.VAR_MAC;

    String MATCHING_CREDENTIALS_JSON                 = "matchingCredentials";

    String MAX_LENGTH_JSON                           = SecureKeyStore.VAR_MAX_LENGTH;

    String MIME_TYPE_JSON                            = "mimeType";

    String MIN_LENGTH_JSON                           = SecureKeyStore.VAR_MIN_LENGTH;

    String NAME_JSON                                 = SecureKeyStore.VAR_NAME;

    String NONCE_JSON                                = SecureKeyStore.VAR_NONCE;

    String PATTERN_RESTRICTIONS_JSON                 = SecureKeyStore.VAR_PATTERN_RESTRICTIONS;

    String PIN_POLICY_SPECIFIERS_JSON                = "pinPolicySpecifiers";       

    String PREFERREDD_LANGUAGES_JSON                 = "preferredLanguages";

    String PRIVACY_ENABLED_JSON                      = SecureKeyStore.VAR_PRIVACY_ENABLED;

    String PROPERTIES_JSON                           = "properties";       

    String PROPERTY_BAGS_JSON                        = SecureKeyStore.VAR_PROPERTY_BAG + "s";       

    String PUK_POLICY_SPECIFIERS_JSON                = "pukPolicySpecifiers";       

    String RETRY_LIMIT_JSON                          = SecureKeyStore.VAR_RETRY_LIMIT;

    String SEARCH_FILTER_JSON                        = "searchFilter";

    String SERVER_EPHEMERAL_KEY_JSON                 = SecureKeyStore.VAR_SERVER_EPHEMERAL_KEY;

    String SERVER_CERT_FP_JSON                       = "serverCertificateFingerPrint";

    String SERVER_SEED_JSON                          = SecureKeyStore.VAR_SERVER_SEED;
    
    String SERVER_SESSION_ID_JSON                    = SecureKeyStore.VAR_SERVER_SESSION_ID;

    String SERVER_TIME_JSON                          = SecureKeyStore.VAR_SERVER_TIME;

    String SESSION_KEY_ALGORITHM_JSON                = SecureKeyStore.VAR_SESSION_KEY_ALGORITHM;

    String SESSION_KEY_LIMIT_JSON                    = SecureKeyStore.VAR_SESSION_KEY_LIMIT;

    String SESSION_LIFE_TIME_JSON                    = SecureKeyStore.VAR_SESSION_LIFE_TIME;

    String SUPPORTED_JSON                            = "supported";

    String TRUST_ANCHOR_JSON                         = "trustAnchor";

    String TYPE_JSON                                 = SecureKeyStore.VAR_TYPE;

    String UNLOCK_KEYS_JSON                          = "unlockKeys";

    String UPDATABLE_KEY_MANAGEMENT_KEYS_JSON        = "updatableKeyManagementKeys";

    String UPDATE_KEY_JSON                           = "updateKey";

    String USER_MODIFIABLE_JSON                      = SecureKeyStore.VAR_USER_MODIFIABLE;

    String VALUE_JSON                                = SecureKeyStore.VAR_VALUE;

    String VALUES_JSON                               = SecureKeyStore.VAR_VALUE + "s";

    String WIDTH_JSON                                = "width";

    String WRITABLE_JSON                             = SecureKeyStore.VAR_WRITABLE;
}
