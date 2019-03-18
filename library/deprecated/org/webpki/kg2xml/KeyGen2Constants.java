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

public interface KeyGen2Constants
  {
    String KEYGEN2_NS                                = "http://xmlns.webpki.org/keygen2/beta/20131201#";

    String KEYGEN2_SCHEMA_FILE                       = "keygen2.xsd";

    // XML attributes

    String ABORT_URL_ATTR                            = "AbortURL";

    String ACTION_ATTR                               = "Action";

    String ALGORITHMS_ATTR                           = "Algorithms";

    String APP_USAGE_ATTR                            = "AppUsage";

    String AUTHORIZATION_ATTR                        = "Authorization";

    String BIOMETRIC_PROTECTION_ATTR                 = "BiometricProtection";

    String CLIENT_SESSION_ID_ATTR                    = "ClientSessionID";

    String CLIENT_TIME_ATTR                          = "ClientTime";

    String DEFERRED_CERTIFICATION_ATTR               = "DeferredCertification";

    String DELETE_PROTECTION_ATTR                    = "DeleteProtection";

    String ENABLE_PIN_CACHING_ATTR                   = "EnablePINCaching";

    String ENDORSED_ALGORITHMS_ATTR                  = "EndorsedAlgorithms";

    String EXPORT_PROTECTION_ATTR                    = "ExportProtection";

    String EXTENSIONS_ATTR                           = "Extensions";

    String CHALLENGE_ATTR                            = "Challenge";

    String CLIENT_ATTRIBUTES_ATTR                    = "ClientAttributes";

    String CLOSE_ATTESTATION_ATTR                    = "CloseAttestation";

    String DEVICE_PIN_PROTECTION_ATTR                = "DevicePINProtection";

    String FORMAT_ATTR                               = "Format";

    String FRIENDLY_NAME_ATTR                        = "FriendlyName";

    String GROUPING_ATTR                             = "Grouping";

    String HEIGHT_ATTR                               = "Height";

    String ID_ATTR                                   = "ID";

    String INPUT_METHOD_ATTR                         = "InputMethod";

    String ISSUED_BEFORE_ATTR                        = "IssuedBefore";

    String ISSUED_AFTER_ATTR                         = "IssuedAfter";

    String KEY_ALGORITHM_ATTR                        = "KeyAlgorithm";

    String KEY_ATTESTATION_ATTR                      = "KeyAttestation";

    String KEY_ENTRY_ALGORITHM_ATTR                  = "KeyEntryAlgorithm";

    String KEY_PARAMETERS_ATTR                       = "KeyParameters";

    String PREFERRED_LANGUAGES_ATTR                  = "PreferredLanguages";

    String LOCKED_ATTR                               = "Locked";

    String MAC_ATTR                                  = "MAC";

    String MAX_LENGTH_ATTR                           = "MaxLength";

    String MIME_TYPE_ATTR                            = "MimeType";

    String MIN_LENGTH_ATTR                           = "MinLength";

    String NAME_ATTR                                 = "Name";

    String NONCE_ATTR                                = "Nonce";

    String PATTERN_RESTRICTIONS_ATTR                 = "PatternRestrictions";

    String ENCRYPTED_PRESET_PIN_ATTR                 = "EncryptedPresetPIN";
    
    String PRIVACY_ENABLED_ATTR                      = "PrivacyEnabled";

    String RETRY_LIMIT_ATTR                          = "RetryLimit";

    String REQUESTED_CLIENT_ATTRIBUTES_ATTR          = "RequestedClientAttributes";

    String SERVER_CERT_FP_ATTR                       = "ServerCertificateFingerPrint";

    String SERVER_SEED_ATTR                          = "ServerSeed";
    
    String SERVER_SESSION_ID_ATTR                    = "ServerSessionID";

    String SERVER_TIME_ATTR                          = "ServerTime";

    String SESSION_ATTESTATION_ATTR                  = "SessionAttestation";

    String SESSION_KEY_ALGORITHM_ATTR                = "SessionKeyAlgorithm";

    String SESSION_KEY_LIMIT_ATTR                    = "SessionKeyLimit";

    String SESSION_LIFE_TIME_ATTR                    = "SessionLifeTime";

    String SUBMIT_URL_ATTR                           = "SubmitURL";

    String TRUST_ANCHOR_ATTR                         = "TrustAnchor";

    String TYPE_ATTR                                 = "Type";

    String USER_MODIFIABLE_ATTR                      = "UserModifiable";

    String VALUE_ATTR                                = "Value";

    String WIDTH_ATTR                                = "Width";

    String WRITABLE_ATTR                             = "Writable";


    // XML elements
    
    String CLIENT_ATTRIBUTE_ELEM                     = "ClientAttribute";

    String CLIENT_EPHEMERAL_KEY_ELEM                 = "ClientEphemeralKey";

    String CLONE_KEY_PROTECTION_ELEM                 = "CloneKeyProtection";
    
    String CREDENTIAL_DISCOVERY_REQUEST_ELEM         = "CredentialDiscoveryRequest";

    String CREDENTIAL_DISCOVERY_RESPONSE_ELEM        = "CredentialDiscoveryResponse";
    
    String DELETE_KEY_ELEM                           = "DeleteKey";
    
    String DEVICE_CERTIFICATE_ELEM                   = "DeviceCertificate";

    String EXTENSION_ELEM                            = "Extension";

    String ENCRYPTED_EXTENSION_ELEM                  = "EncryptedExtension";

    String ENCRYPTED_PUK_ATTR                        = "EncryptedPUK";
    
    String GENERATED_KEY_ELEM                        = "GeneratedKey";

    String IMAGE_PREFERENCE_ELEM                     = "ImagePreference";

    String IMPORT_KEY_ELEM                           = "ImportKey";

    String ISSUED_CREDENTIAL_ELEM                    = "IssuedCredential";

    String KEY_CREATION_REQUEST_ELEM                 = "KeyCreationRequest";
    
    String KEY_CREATION_RESPONSE_ELEM                = "KeyCreationResponse";

    String KEY_ENTRY_SPECIFIER_ELEM                  = "KeyEntrySpecifier";       

    String KEY_MANAGEMENT_KEY_ELEM                   = "KeyManagementKey";

    String MATCHING_CREDENTIAL_ELEM                  = "MatchingCredential";

    String LOGOTYPE_ELEM                             = "Logotype";

    String LOOKUP_RESULT_ELEM                        = "LookupResult";

    String LOOKUP_SPECIFIER_ELEM                     = "LookupSpecifier";

    String PIN_POLICY_SPECIFIER_ELEM                 = "PINPolicySpecifier";       

    String PLATFORM_NEGOTIATION_REQUEST_ELEM         = "PlatformNegotiationRequest";
    
    String PLATFORM_NEGOTIATION_RESPONSE_ELEM        = "PlatformNegotiationResponse";
    
    String PRIVATE_KEY_ELEM                          = "PrivateKey";

    String PROPERTY_BAG_ELEM                         = "PropertyBag";       

    String PROPERTY_ELEM                             = "Property";       

    String PROVISIONING_INITIALIZATION_REQUEST_ELEM  = "ProvisioningInitializationRequest";
    
    String PROVISIONING_INITIALIZATION_RESPONSE_ELEM = "ProvisioningInitializationResponse";

    String PROVISIONING_FINALIZATION_REQUEST_ELEM    = "ProvisioningFinalizationRequest";
    
    String PROVISIONING_FINALIZATION_RESPONSE_ELEM   = "ProvisioningFinalizationResponse";

    String PUK_POLICY_SPECIFIER_ELEM                 = "PUKPolicySpecifier";       

    String SERVER_EPHEMERAL_KEY_ELEM                 = "ServerEphemeralKey";

    String SYMMETRIC_KEY_ELEM                        = "SymmetricKey";

    String SEARCH_FILTER_ELEM                        = "SearchFilter";

    String UNLOCK_KEY_ELEM                           = "UnlockKey";

    String UPDATABLE_KEY_MANAGEMENT_KEY_ELEM         = "UpdatableKeyManagementKey";

    String UPDATE_KEY_ELEM                           = "UpdateKey";

    String VIRTUAL_MACHINE_ELEM                      = "VirtualMachine";
  }
