/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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

import java.lang.reflect.InvocationTargetException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.io.IOException;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyTypes;
import org.webpki.crypto.OkpSupport;

/**
 * Common crypto support for JSF and JEF.
 */
public class JSONCryptoHelper {

    private JSONCryptoHelper() {}

    // Arguments
    public static final String OKP_PUBLIC_KEY          = "OKP";

    public static final String EC_PUBLIC_KEY           = "EC";

    public static final String RSA_PUBLIC_KEY          = "RSA";

    // JSON properties
    public static final String ALGORITHM_JSON          = "algorithm";

    public static final String CERTIFICATE_PATH_JSON   = "certificatePath";// X.509 Certificate path

    public static final String CHAIN_JSON              = "chain";          // JSF specific

    public static final String CIPHER_TEXT_JSON        = "cipherText";     // JEF specific

    public static final String CRV_JSON                = "crv";            // JWK

    public static final String E_JSON                  = "e";              // JWK

    public static final String ENCRYPTED_KEY_JSON      = "encryptedKey";   // JWE/JEF specific

    public static final String EPHEMERAL_KEY_JSON      = "ephemeralKey";   // JWK subset

    public static final String EXCLUDES_JSON           = "excludes";       // JSF specific non-protected

    public static final String EXTENSIONS_JSON         = "extensions";     // JSF/JEF extensions

    public static final String IV_JSON                 = "iv";             // JWE/JEF

    public static final String KEY_ENCRYPTION_JSON     = "keyEncryption";  // JEF

    public static final String KEY_ID_JSON             = "keyId";          // JSF/JEF

    public static final String KTY_JSON                = "kty";            // JWK

    public static final String N_JSON                  = "n";              // JWK

    public static final String PUBLIC_KEY_JSON         = "publicKey";      // Public key holder (subset JWK)

    public static final String RECIPIENTS_JSON         = "recipients";     // JEF specific

    public static final String SIGNERS_JSON            = "signers";        // JSF - Multiple signers

    public static final String TAG_JSON                = "tag";            // JWE/JEF

    public static final String VALUE_JSON              = "value";          // JSF signature value 

    public static final String X_JSON                  = "x";              // JWK

    public static final String Y_JSON                  = "y";              // JWK
    
    
    static final LinkedHashSet<String> jefReservedWords = new LinkedHashSet<>();

    static {
        jefReservedWords.add(ALGORITHM_JSON);
        jefReservedWords.add(CERTIFICATE_PATH_JSON);
        jefReservedWords.add(CIPHER_TEXT_JSON);
        jefReservedWords.add(ENCRYPTED_KEY_JSON);
        jefReservedWords.add(EPHEMERAL_KEY_JSON);
        jefReservedWords.add(EXTENSIONS_JSON);
        jefReservedWords.add(IV_JSON);
        jefReservedWords.add(KEY_ENCRYPTION_JSON);
        jefReservedWords.add(KEY_ID_JSON);
        jefReservedWords.add(PUBLIC_KEY_JSON);
        jefReservedWords.add(RECIPIENTS_JSON);
        jefReservedWords.add(TAG_JSON);
    }

    static final LinkedHashSet<String> jsfReservedWords = new LinkedHashSet<>();

    static {
        jsfReservedWords.add(ALGORITHM_JSON);
        jsfReservedWords.add(CERTIFICATE_PATH_JSON);
        jsfReservedWords.add(CHAIN_JSON);
        jsfReservedWords.add(EXTENSIONS_JSON);
        jsfReservedWords.add(EXCLUDES_JSON);
        jsfReservedWords.add(KEY_ID_JSON);
        jsfReservedWords.add(PUBLIC_KEY_JSON);
        jsfReservedWords.add(SIGNERS_JSON);
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
        
        LinkedHashMap<String,ExtensionEntry> extensions = 
                new LinkedHashMap<>();

        public ExtensionHolder addExtension(Class<? extends Extension> extensionClass,
                                            boolean mandatory) throws IOException {
            try {
                Extension extension = extensionClass.getDeclaredConstructor().newInstance();
                ExtensionEntry extensionEntry = new ExtensionEntry();
                extensionEntry.extensionClass = extensionClass;
                extensionEntry.mandatory = mandatory;
                if ((extensions.put(extension.getExtensionUri(), extensionEntry)) != null) {
                    throw new IOException("Duplicate extension: " + extension.getExtensionUri());
                }
            } catch (InstantiationException | InvocationTargetException | 
                     NoSuchMethodException | IllegalAccessException e) {
                throw new IOException (e);
            }
            return this;
        }
        
        String[] getPropertyList() {
            return extensions.keySet().toArray(new String[0]);
        }
    }

    /**
     * KeyID parameter to Options
     *
     */
    public enum KEY_ID_OPTIONS {FORBIDDEN, REQUIRED, OPTIONAL};

    /**
     * Public key parameter to Options
     * 
     */
    public enum PUBLIC_KEY_OPTIONS {
        /**
         * Only valid for encryption = No key encryption
         */
        PLAIN_ENCRYPTION      (),

        /**
         * Key encryption but no public key or certificate path
         */
        FORBIDDEN             (), 

        /**
         * Key encryption with public key
         */
        REQUIRED              (), 

        /**
         * Key encryption with optional public key
         */
        OPTIONAL              (), 

        /**
         * Key encryption with at least a public key or a key id
         */
        KEY_ID_OR_PUBLIC_KEY  (),

        /**
         * key encryption with a public key or a key id
         */
        KEY_ID_XOR_PUBLIC_KEY (),

        /**
         * Key encryption with a certificate path
         */
        CERTIFICATE_PATH      ();
        
        private boolean keyIdTest(String keyId) {
            return keyId == null && this == KEY_ID_XOR_PUBLIC_KEY;
        }

        void checkPublicKey(String keyId) throws IOException {
            if (this == FORBIDDEN || (this != REQUIRED && 
                                      this != OPTIONAL &&
                                      this != KEY_ID_OR_PUBLIC_KEY &&
                                      !keyIdTest(keyId))) {
                throw new IOException("Unexpected \"" + PUBLIC_KEY_JSON + "\"");
            }
        }

        void checkCertificatePath() throws IOException {
            if (this != CERTIFICATE_PATH) {
                throw new IOException("Unexpected \"" + CERTIFICATE_PATH_JSON + "\"");
            }
        }

        void checkMissingKey(String keyId) throws IOException {
            if (this == REQUIRED || 
                this == CERTIFICATE_PATH ||
                (keyId == null && this == KEY_ID_OR_PUBLIC_KEY) ||
                keyIdTest(keyId)) {
                throw new IOException("Missing key information");
            }
        }
    };

    /**
     * Common JEF/JSF decoding options.
     * <p>This class holds options that are checked during decoding.</p>
     * The following options are currently recognized:
     * <ul>
     * <li>Algorithm preference.  Default: JOSE</li>
     * <li>Public key option.  Default: OPTIONAL</li>
     * <li>keyId option.  Default: OPTIONAL</li>
     * <li>Permitted extensions.  Default: none</li>
     * </ul>
     *
     */
    public static class Options {
        
        AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE;
        PUBLIC_KEY_OPTIONS publicKeyOption = PUBLIC_KEY_OPTIONS.OPTIONAL;
        KEY_ID_OPTIONS keyIdOption = KEY_ID_OPTIONS.OPTIONAL;
        ExtensionHolder extensionHolder = new ExtensionHolder();
        LinkedHashSet<String> exclusions;
        boolean encryptionMode;
        
        public Options setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
            this.algorithmPreferences = algorithmPreferences;
            return this;
        }

        public Options setPublicKeyOption(PUBLIC_KEY_OPTIONS publicKeyOption) {
            this.publicKeyOption = publicKeyOption;
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

        void initializeOperation(boolean encryptionMode) throws IOException {
            this.encryptionMode = encryptionMode;
            if (encryptionMode) {
                if (exclusions != null) {
                    throw new IOException("\"setPermittedExclusions()\" " +
                                          "is not applicable to encryption");
                }
            } else if (publicKeyOption == PUBLIC_KEY_OPTIONS.PLAIN_ENCRYPTION) {
                throw new IOException("\"" + PUBLIC_KEY_OPTIONS.PLAIN_ENCRYPTION + 
                                     "\" is not applicable to signatures");
            }
            if (keyIdOption != KEY_ID_OPTIONS.OPTIONAL &&
                 (publicKeyOption == PUBLIC_KEY_OPTIONS.KEY_ID_OR_PUBLIC_KEY ||
                  publicKeyOption == PUBLIC_KEY_OPTIONS.KEY_ID_XOR_PUBLIC_KEY)) {
                throw new IOException("Invalid key id and public key option combination");
            }
            for (String extension : extensionHolder.extensions.keySet()) {
                checkOneExtension(extension, encryptionMode);
            }
        }

        String getKeyId(JSONObjectReader reader) throws IOException {
            String keyId = reader.getStringConditional(JSONCryptoHelper.KEY_ID_JSON);
            if (keyId == null) {
                if (keyIdOption == JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED) {
                    throw new IOException("Missing \"" + JSONCryptoHelper.KEY_ID_JSON + "\"");
                }
            } else if (keyIdOption == JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN) {
                throw new IOException("Unexpected \"" + JSONCryptoHelper.KEY_ID_JSON + "\"");
            }
            return keyId;
        }

        void getExtensions(JSONObjectReader innerObject, 
                           JSONObjectReader outerObject,
                           LinkedHashMap<String, Extension> extensions) throws IOException {
            String[] extensionList = 
                    outerObject.getStringArrayConditional(JSONCryptoHelper.EXTENSIONS_JSON);
            if (extensionList == null) {
                for (String name : extensionHolder.extensions.keySet()) {
                    if (extensionHolder.extensions.get(name).mandatory) {
                        throw new IOException("Missing \"" + 
                                             JSONCryptoHelper.EXTENSIONS_JSON + 
                                             "\" mandatory extension: " + name);
                    }
                }
            } else {
                checkExtensions(extensionList, encryptionMode);
                if (extensionHolder.extensions.isEmpty()) {
                    throw new IOException("Use of \"" + 
                                          JSONCryptoHelper.EXTENSIONS_JSON + 
                                          "\" must be set in options");
                }
                for (String name : extensionList) {
                    JSONCryptoHelper.ExtensionEntry extensionEntry = 
                            extensionHolder.extensions.get(name);
                    if (extensionEntry == null) {
                        throw new IOException("Unexpected \"" + 
                                              JSONCryptoHelper.EXTENSIONS_JSON + 
                                              "\" extension: " + name);
                    }
                    if (innerObject.hasProperty(name)) {
                        try {
                            JSONCryptoHelper.Extension extension = 
                                    extensionEntry.extensionClass.getDeclaredConstructor().newInstance();
                            extension.decode(innerObject);
                            extensions.put(name, extension);
                        } catch (InstantiationException | InvocationTargetException | 
                                 NoSuchMethodException | IllegalAccessException e) {
                            throw new IOException (e);
                        }
                    }
                }
            }
            for (String name : extensionHolder.extensions.keySet()) {
                if (!extensions.containsKey(name) && 
                    extensionHolder.extensions.get(name).mandatory) {
                    throw new IOException("Missing \"" + 
                                          JSONCryptoHelper.EXTENSIONS_JSON + 
                                          "\" mandatory extension: " + name);
                }
            }
        }
    }

    private static void checkOneExtension(String property, 
                                          boolean encryptionMode) throws IOException {
        if ((encryptionMode ? jefReservedWords : jsfReservedWords).contains(property)) {
            throw new IOException("Forbidden \"" + 
                                  JSONCryptoHelper.EXTENSIONS_JSON + 
                                  "\" property: " + property);
        }
    }

    static String[] checkExtensions(String[] properties, 
                                    boolean encryptionMode) throws IOException {
        if (properties.length == 0) {
            throw new IOException("Empty \"" + 
                                  JSONCryptoHelper.EXTENSIONS_JSON + 
                                  "\" array not allowed");
        }
        for (String property : properties) {
            checkOneExtension(property, encryptionMode);
        }
        return properties;
    }

    static LinkedHashSet<String> createSet(String[] listOfNames) throws IOException {
        LinkedHashSet<String> set = new LinkedHashSet<>();
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
    
    static BigInteger getCurvePoint(JSONObjectReader rd, 
                                    String property,
                                    KeyAlgorithms ec) throws IOException {
        byte[] fixedBinary = rd.getBinary(property);
        if (fixedBinary.length != (ec.getPublicKeySizeInBits() + 7) / 8) {
            throw new IOException("Public EC key parameter \"" + property + "\" is not normalized");
        }
        return new BigInteger(1, fixedBinary);
    }

    static BigInteger getCryptoBinary(JSONObjectReader rd, 
                                      String property) throws IOException {
        byte[] cryptoBinary = rd.getBinary(property);
        if (cryptoBinary[0] == 0x00) {
            throw new IOException("RSA key parameter \"" + 
                                  property + 
                                  "\" contains leading zeroes");
        }
        return new BigInteger(1, cryptoBinary);
    }

    public static PublicKey decodePublicKey(JSONObjectReader rd,
                                            AlgorithmPreferences algorithmPreferences) 
            throws IOException, GeneralSecurityException {
        PublicKey publicKey = null;
            String kty = rd.getString(JSONCryptoHelper.KTY_JSON);
            KeyAlgorithms keyAlgorithm;
            switch (kty) {
            case JSONCryptoHelper.RSA_PUBLIC_KEY:
                publicKey = KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(getCryptoBinary(rd, JSONCryptoHelper.N_JSON),
                                             getCryptoBinary(rd, JSONCryptoHelper.E_JSON)));
                break;
            case JSONCryptoHelper.EC_PUBLIC_KEY:
                keyAlgorithm = KeyAlgorithms.getKeyAlgorithmFromId(
                        rd.getString(JSONCryptoHelper.CRV_JSON),
                        algorithmPreferences);
                if (keyAlgorithm.getKeyType() != KeyTypes.EC) {
                    throw new IllegalArgumentException("\"" + JSONCryptoHelper.CRV_JSON + 
                                                       "\" is not an EC type");
                }
                ECPoint w = new ECPoint(getCurvePoint(rd, JSONCryptoHelper.X_JSON, keyAlgorithm),
                                        getCurvePoint(rd, JSONCryptoHelper.Y_JSON, keyAlgorithm));
                publicKey = KeyFactory.getInstance("EC")
                        .generatePublic(new ECPublicKeySpec(w, keyAlgorithm.getECParameterSpec()));
                break;
            case JSONCryptoHelper.OKP_PUBLIC_KEY:
                keyAlgorithm = KeyAlgorithms.getKeyAlgorithmFromId(
                        rd.getString(JSONCryptoHelper.CRV_JSON),
                        algorithmPreferences);
                if (keyAlgorithm.getKeyType() != KeyTypes.EDDSA &&
                    keyAlgorithm.getKeyType() != KeyTypes.XEC) {
                    throw new IllegalArgumentException("\"" + JSONCryptoHelper.CRV_JSON + 
                                                       "\" is not a valid OKP type");
                }
                publicKey = OkpSupport.raw2PublicOkpKey(rd.getBinary(JSONCryptoHelper.X_JSON), 
                                                        keyAlgorithm);
                break;
            default:
                throw new IllegalArgumentException("Unrecognized \"" + 
                                                   JSONCryptoHelper.KTY_JSON + "\": " + kty);
            }
            return publicKey;

    }

    public static PrivateKey decodePrivateKey(JSONObjectReader rd,
                                              PublicKey publicKey) 
           throws IOException, GeneralSecurityException {
        KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
        switch (keyAlgorithm.getKeyType()) {
        case EC:
            return KeyFactory.getInstance("EC").generatePrivate(
                    new ECPrivateKeySpec(getCurvePoint(rd, "d", keyAlgorithm),
                                         keyAlgorithm.getECParameterSpec()));
        case RSA:
            return KeyFactory.getInstance("RSA").generatePrivate(
                    new RSAPrivateCrtKeySpec(((RSAPublicKey) publicKey).getModulus(),
                                             ((RSAPublicKey) publicKey).getPublicExponent(),
                                             getCryptoBinary(rd, "d"),
                                             getCryptoBinary(rd, "p"),
                                             getCryptoBinary(rd, "q"),
                                             getCryptoBinary(rd, "dp"),
                                             getCryptoBinary(rd, "dq"),
                                             getCryptoBinary(rd, "qi")));
        default:
            return OkpSupport.raw2PrivateOkpKey(rd.getBinary("d"), keyAlgorithm);
        }
    }
 }
