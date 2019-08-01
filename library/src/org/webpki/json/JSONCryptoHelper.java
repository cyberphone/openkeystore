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
package org.webpki.json;

import java.io.IOException;
import java.io.Serializable;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

import org.webpki.crypto.AlgorithmPreferences;

/**
 * Common crypto support for JSF and JEF.
 */
public class JSONCryptoHelper implements Serializable {

    private static final long serialVersionUID = 1L;

    private JSONCryptoHelper() {}

    // Arguments
    public static final String EC_PUBLIC_KEY           = "EC";

    public static final String RSA_PUBLIC_KEY          = "RSA";

    // JSON properties
    public static final String ALGORITHM_JSON          = "algorithm";

    public static final String CERTIFICATE_PATH_JSON   = "certificatePath";// X.509 Certificate path

    public static final String CIPHER_TEXT_JSON        = "cipherText";     // JEF specific

    public static final String CRV_JSON                = "crv";            // JWK

    public static final String E_JSON                  = "e";              // JWK

    public static final String ENCRYPTED_KEY_JSON      = "encryptedKey";   // JEF specific

    public static final String RECIPIENTS_JSON         = "recipients";     // JEF specific

    public static final String EPHEMERAL_KEY_JSON      = "ephemeralKey";   // JWK subset

    public static final String EXCLUDES_JSON           = "excludes";       // JSF specific non-protected

    public static final String EXTENSIONS_JSON         = "extensions";     // JSF/JEF extensions

    public static final String IV_JSON                 = "iv";             // JWE/JEF

    public static final String KEY_ID_JSON             = "keyId";          // JSF/JEF

    public static final String KTY_JSON                = "kty";            // JWK

    public static final String N_JSON                  = "n";              // JWK

    public static final String PUBLIC_KEY_JSON         = "publicKey";      // Public key holder (subset JWK)

    public static final String SIGNERS_JSON            = "signers";        // JSF - Multiple signers

    public static final String TAG_JSON                = "tag";            // JWE/JEF

    public static final String VALUE_JSON              = "value";          // JSF signature value 

    public static final String X_JSON                  = "x";              // JWK

    public static final String Y_JSON                  = "y";              // JWK
    
    
    static final LinkedHashSet<String> jefReservedWords = new LinkedHashSet<String>();

    static {
        jefReservedWords.add(ALGORITHM_JSON);
        jefReservedWords.add(IV_JSON);
        jefReservedWords.add(TAG_JSON);
        jefReservedWords.add(ENCRYPTED_KEY_JSON);
        jefReservedWords.add(EPHEMERAL_KEY_JSON);
        jefReservedWords.add(CIPHER_TEXT_JSON);
        jefReservedWords.add(RECIPIENTS_JSON);
        jefReservedWords.add(EXTENSIONS_JSON);
        jefReservedWords.add(KEY_ID_JSON);
        jefReservedWords.add(PUBLIC_KEY_JSON);
        jefReservedWords.add(CERTIFICATE_PATH_JSON);
    }

    static final LinkedHashSet<String> jsfReservedWords = new LinkedHashSet<String>();

    static {
        jsfReservedWords.add(ALGORITHM_JSON);
        jsfReservedWords.add(EXTENSIONS_JSON);
        jsfReservedWords.add(EXCLUDES_JSON);
        jsfReservedWords.add(KEY_ID_JSON);
        jsfReservedWords.add(PUBLIC_KEY_JSON);
        jsfReservedWords.add(CERTIFICATE_PATH_JSON);
        jsfReservedWords.add(VALUE_JSON);
    }

    /**
     * For building "extensions" decoders
     */
    public static abstract class Extension {
        
        public abstract String getExtensionUri();
        
        protected abstract void decode(JSONObjectReader reader) throws IOException;
    }

    static class ExtensionEntry {
        Class<? extends Extension> extensionClass;
        boolean mandatory;
    }

    /**
     * Holds list of supported "extensions" decoders.
     *
     */
    public static class ExtensionHolder {
        
        LinkedHashMap<String,ExtensionEntry> extensions = new LinkedHashMap<String,ExtensionEntry>();

        public ExtensionHolder addExtension(Class<? extends Extension> extensionClass,
                                            boolean mandatory) throws IOException {
            try {
                Extension extension = extensionClass.newInstance();
                ExtensionEntry extensionEntry = new ExtensionEntry();
                extensionEntry.extensionClass = extensionClass;
                extensionEntry.mandatory = mandatory;
                if ((extensions.put(extension.getExtensionUri(), extensionEntry)) != null) {
                    throw new IOException("Duplicate extension: " + extension.getExtensionUri());
                }
            } catch (InstantiationException e) {
                throw new IOException(e);
            } catch (IllegalAccessException e) {
                throw new IOException(e);
            }
            return this;
        }
        
        String[] getPropertyList() {
            return extensions.keySet().toArray(new String[0]);
        }
    }

    /**
     * Parameter to Options
     *
     */
    public enum KEY_ID_OPTIONS {FORBIDDEN, REQUIRED, OPTIONAL};

    /**
     * Common JEF/JSF decoding options.
     * <p>This class holds options that are checked during decoding.</p>
     * The following options are currently recognized:
     * <ul>
     * <li>Algorithm preference.  Default: JOSE</li>
     * <li>Require public key info in line.  Default: true</li>
     * <li>keyId option.  Default: FORBIDDEN</li>
     * <li>Permitted extensions.  Default: none</li>
     * </ul>
     * In addition, the Options class is used for defining external readers for &quot;remoteKey&quot; support.
     *
     */
    public static class Options {
        
        AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE;
        boolean requirePublicKeyInfo = true;
        KEY_ID_OPTIONS keyIdOption = KEY_ID_OPTIONS.FORBIDDEN;
        ExtensionHolder extensionHolder = new ExtensionHolder();
        LinkedHashSet<String> exclusions;
        boolean encryptionMode;
        
        public Options setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
            this.algorithmPreferences = algorithmPreferences;
            return this;
        }

        public Options setRequirePublicKeyInfo(boolean flag) {
            this.requirePublicKeyInfo = flag;
            return this;
        }

        public Options setKeyIdOption(KEY_ID_OPTIONS keyIdOption) {
            this.keyIdOption = keyIdOption;
            return this;
        }

        public Options setPermittedExtensions(ExtensionHolder extensionHolder) {
            this.extensionHolder = extensionHolder;
            return this;
        }

        public Options setPermittedExclusions(String[] exclusions) throws IOException {
            this.exclusions = JSONSignatureDecoder.checkExcluded(exclusions);
            return this;
        }

        void encryptionMode(boolean flag) throws IOException {
            encryptionMode = flag;
            if (flag) {
                if (exclusions != null) {
                    throw new IOException("\"setPermittedExclusions()\" is not applicable to encryption");
                }
            }
            for (String extension : extensionHolder.extensions.keySet()) {
                checkOneExtension(extension, flag);
            }
        }

        String getKeyId(JSONObjectReader reader) throws IOException {
            String keyId = reader.getStringConditional(JSONCryptoHelper.KEY_ID_JSON);
            if (keyId == null) {
                if (keyIdOption == JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED) {
                    throw new IOException("Missing \"" + JSONCryptoHelper.KEY_ID_JSON + "\"");
                }
            } else if (keyIdOption == JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN) {
                throw new IOException("Use of \"" + JSONCryptoHelper.KEY_ID_JSON + "\" must be set in options");
            }
            return keyId;
        }

        void getExtensions(JSONObjectReader innerObject, JSONObjectReader outerObject, LinkedHashMap<String, Extension> extensions) throws IOException {
            String[] extensionList = outerObject.getStringArrayConditional(JSONCryptoHelper.EXTENSIONS_JSON);
            if (extensionList == null) {
                for (String name : extensionHolder.extensions.keySet()) {
                    if (extensionHolder.extensions.get(name).mandatory) {
                        throw new IOException("Missing \"" + JSONCryptoHelper.EXTENSIONS_JSON + "\" mandatory extension: " + name);
                    }
                }
            } else {
                checkExtensions(extensionList, encryptionMode);
                if (extensionHolder.extensions.isEmpty()) {
                    throw new IOException("Use of \"" + JSONCryptoHelper.EXTENSIONS_JSON + "\" must be set in options");
                }
                for (String name : extensionList) {
                    JSONCryptoHelper.ExtensionEntry extensionEntry = extensionHolder.extensions.get(name);
                    if (extensionEntry == null) {
                        throw new IOException("Unexpected \"" + JSONCryptoHelper.EXTENSIONS_JSON + "\" extension: " + name);
                    }
                    if (innerObject.hasProperty(name)) {
                        try {
                            JSONCryptoHelper.Extension extension = extensionEntry.extensionClass.newInstance();
                            extension.decode(innerObject);
                            extensions.put(name, extension);
                        } catch (InstantiationException e) {
                            throw new IOException (e);
                        } catch (IllegalAccessException e) {
                            throw new IOException (e);
                        }
                    }
                }
            }
            for (String name : extensionHolder.extensions.keySet()) {
                if (!extensions.containsKey(name) && extensionHolder.extensions.get(name).mandatory) {
                    throw new IOException("Missing \"" + JSONCryptoHelper.EXTENSIONS_JSON + "\" mandatory extension: " + name);
                }
            }
        }
    }

    private static void checkOneExtension(String property, boolean encryptionMode) throws IOException {
        if ((encryptionMode ? jefReservedWords : jsfReservedWords).contains(property)) {
            throw new IOException("Forbidden \"" + JSONCryptoHelper.EXTENSIONS_JSON + "\" property: " + property);
        }
    }

    static String[] checkExtensions(String[] properties, boolean encryptionMode) throws IOException {
        if (properties.length == 0) {
            throw new IOException("Empty \"" + JSONCryptoHelper.EXTENSIONS_JSON + "\" array not allowed");
        }
        for (String property : properties) {
            checkOneExtension(property, encryptionMode);
        }
        return properties;
    }

    static LinkedHashSet<String> createSet(String[] listOfNames) throws IOException {
        LinkedHashSet<String> set = new LinkedHashSet<String>();
        for (String name : listOfNames) {
            if (!set.add(name)) {
               throw new IOException("Duplicate: \"" + name + "\""); 
            }
        }
        return set;
    }
    
    static class ExtensionsEncoder {
        
        LinkedHashSet<String> extensionNames;
        
        public void setExtensionNames(String[] names, boolean encryptionMode) throws IOException {
            this.extensionNames = createSet(checkExtensions(names, encryptionMode));
        }
    }
 }
