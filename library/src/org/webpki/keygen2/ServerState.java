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

import static org.webpki.keygen2.KeyGen2Constants.*;

import java.io.IOException;
import java.io.Serializable;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.DeviceID;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyContainerTypes;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeyVerifierInterface;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSymKeyVerifier;

import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;
import org.webpki.util.ISODateTime;
import org.webpki.util.MIMETypedObject;

public class ServerState implements Serializable {

    private static final long serialVersionUID = 1L;

    public enum ProtocolPhase {INVOCATION,
                               PROVISIONING_INITIALIZATION,
                               CREDENTIAL_DISCOVERY,
                               KEY_CREATION,
                               PROVISIONING_FINALIZATION,
                               DONE}

    enum PostOperation {

        DELETE_KEY           (SecureKeyStore.METHOD_POST_DELETE_KEY,           DELETE_KEYS_JSON),
        UNLOCK_KEY           (SecureKeyStore.METHOD_POST_UNLOCK_KEY,           UNLOCK_KEYS_JSON),
        UPDATE_KEY           (SecureKeyStore.METHOD_POST_UPDATE_KEY,           UPDATE_KEY_JSON),
        CLONE_KEY_PROTECTION (SecureKeyStore.METHOD_POST_CLONE_KEY_PROTECTION, CLONE_KEY_PROTECTION_JSON);

        private byte[] method;

        private String jsonProperty;

        PostOperation(byte[] method, String json_prop) {
            this.method = method;
            this.jsonProperty = json_prop;
        }

        byte[] getMethod() {
            return method;
        }

        String getJSONProp() {
            return jsonProperty;
        }
    }

    class PostProvisioningTargetKey implements Serializable {

        private static final long serialVersionUID = 1L;

        String clientSessionId;

        String serverSessionId;

        PublicKey keyManagementKey;

        byte[] certificateData;

        PostOperation postOperation;

        PostProvisioningTargetKey(String clientSessionId,
                                  String serverSessionId,
                                  byte[] certificateData,
                                  PublicKey keyManagementKey,
                                  PostOperation postOperation) {
            this.clientSessionId = clientSessionId;
            this.serverSessionId = serverSessionId;
            this.certificateData = certificateData;
            this.keyManagementKey = keyManagementKey;
            this.postOperation = postOperation;
        }

        private boolean matching(PostProvisioningTargetKey targetKey) {
            return clientSessionId.equals(targetKey.clientSessionId) &&
                   serverSessionId.equals(targetKey.serverSessionId) &&
                   ArrayUtil.compare(certificateData, targetKey.certificateData);
        }
    }

    Vector<PostProvisioningTargetKey> postOperations = new Vector<PostProvisioningTargetKey>();

    public abstract class ExtensionInterface implements Serializable {

        private static final long serialVersionUID = 1L;

        String type;

        public String getType() {
            return type;
        }

        public abstract byte getSubType();

        public String getQualifier() throws IOException {
            return "";
        }

        public abstract String getJSONArrayString();

        public abstract byte[] getExtensionData() throws IOException;

        abstract void writeExtensionBody(JSONObjectWriter wr) throws IOException;

        ExtensionInterface(String type) {
            this.type = type;
        }

        void writeExtension(JSONObjectWriter wr, byte[] macData) throws IOException {
            wr.setString(TYPE_JSON, type);
            writeExtensionBody(wr);
            wr.setBinary(MAC_JSON, macData);
        }
    }

    public class Extension extends ExtensionInterface implements Serializable {

        private static final long serialVersionUID = 1L;

        byte[] data;

        Extension(String type, byte[] data) {
            super(type);
            this.data = data;
        }

        @Override
        public byte getSubType() {
            return SecureKeyStore.SUB_TYPE_EXTENSION;
        }

        @Override
        public byte[] getExtensionData() throws IOException {
            return data;
        }

        @Override
        void writeExtensionBody(JSONObjectWriter wr) throws IOException {
            wr.setBinary(EXTENSION_DATA_JSON, data);
        }

        @Override
        public String getJSONArrayString() {
            return EXTENSIONS_JSON;
        }
    }

    public class EncryptedExtension extends ExtensionInterface implements Serializable {

        private static final long serialVersionUID = 1L;

        byte[] encryptedData;

        EncryptedExtension(String type, byte[] encryptedData) {
            super(type);
            this.encryptedData = encryptedData;
        }

        @Override
        public byte getSubType() {
            return SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION;
        }

        @Override
        public byte[] getExtensionData() throws IOException {
            return encryptedData;
        }

        @Override
        void writeExtensionBody(JSONObjectWriter wr) throws IOException {
            wr.setBinary(EXTENSION_DATA_JSON, encryptedData);
        }

        @Override
        public String getJSONArrayString() {
            return ENCRYPTED_EXTENSIONS_JSON;
        }
    }

    public class Logotype extends ExtensionInterface implements Serializable {

        private static final long serialVersionUID = 1L;

        MIMETypedObject logotype;

        Logotype(String type, MIMETypedObject logotype) {
            super(type);
            this.logotype = logotype;
        }

        @Override
        public byte getSubType() {
            return SecureKeyStore.SUB_TYPE_LOGOTYPE;
        }

        @Override
        public byte[] getExtensionData() throws IOException {
            return logotype.getData();
        }

        @Override
        public String getQualifier() throws IOException {
            return logotype.getMimeType();
        }

        @Override
        void writeExtensionBody(JSONObjectWriter wr) throws IOException {
            wr.setString(MIME_TYPE_JSON, logotype.getMimeType());
            wr.setBinary(EXTENSION_DATA_JSON, logotype.getData());
        }

        @Override
        public String getJSONArrayString() {
            return LOGOTYPES_JSON;
        }
    }

    public class Property implements Serializable {

        private static final long serialVersionUID = 1L;

        String name;

        String value;

        boolean writable;

        private Property() {
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public boolean isWritable() {
            return writable;
        }
    }

    public class PropertyBag extends ExtensionInterface implements Serializable {

        private static final long serialVersionUID = 1L;

        LinkedHashMap<String, Property> properties = new LinkedHashMap<String, Property>();

        public PropertyBag addProperty(String name, String value, boolean writable) throws IOException {
            Property property = new Property();
            property.name = name;
            property.value = value;
            property.writable = writable;
            if (properties.put(name, property) != null) {
                throw new IOException("Duplicate property name \"" + name + "\" not allowed");
            }
            return this;
        }

        PropertyBag(String type) {
            super(type);
        }

        @Override
        public byte getSubType() {
            return SecureKeyStore.SUB_TYPE_PROPERTY_BAG;
        }

        @Override
        public byte[] getExtensionData() throws IOException {
            MacGenerator convert = new MacGenerator();
            for (Property property : properties.values()) {
                convert.addString(property.name);
                convert.addBool(property.writable);
                convert.addString(property.value);
            }
            return convert.getResult();
        }

        public Property[] getProperties() {
            return properties.values().toArray(new Property[0]);
        }

        @Override
        void writeExtensionBody(JSONObjectWriter wr) throws IOException {
            if (properties.isEmpty()) {
                throw new IOException("Empty " + PROPERTY_BAGS_JSON + ": " + type);
            }
            JSONArrayWriter arr = wr.setArray(PROPERTIES_JSON);
            for (Property property : properties.values()) {
                JSONObjectWriter prop_wr = arr.setObject();
                prop_wr.setString(NAME_JSON, property.name);
                prop_wr.setString(VALUE_JSON, property.value);
                if (property.writable) {
                    prop_wr.setBoolean(WRITABLE_JSON, property.writable);
                }
            }
        }

        @Override
        public String getJSONArrayString() {
            return PROPERTY_BAGS_JSON;
        }
    }


    public class PUKPolicy implements Serializable {

        private static final long serialVersionUID = 1L;

        String id;

        byte[] encryptedValue;

        public String getID() {
            return id;
        }

        PassphraseFormat format;

        int retryLimit;

        PUKPolicy(byte[] encryptedValue, PassphraseFormat format, int retryLimit) throws IOException {
            this.encryptedValue = encryptedValue;
            this.id = pukPrefix + ++nextPukIdSuffix;
            this.format = format;
            this.retryLimit = retryLimit;
            pukPolicies.add(this);
        }

        void writePolicy(JSONObjectWriter wr) throws IOException {
            wr.setString(ID_JSON, id);
            wr.setBinary(ENCRYPTED_PUK_JSON, encryptedValue);
            wr.setInt(RETRY_LIMIT_JSON, retryLimit);
            wr.setString(FORMAT_JSON, format.getProtocolName());

            MacGenerator pukPolicyMac = new MacGenerator();
            pukPolicyMac.addString(id);
            pukPolicyMac.addArray(encryptedValue);
            pukPolicyMac.addByte(format.getSksValue());
            pukPolicyMac.addShort(retryLimit);
            wr.setBinary(MAC_JSON, mac(pukPolicyMac.getResult(), SecureKeyStore.METHOD_CREATE_PUK_POLICY));
        }
    }


    public class PINPolicy implements Serializable {

        private static final long serialVersionUID = 1L;

        boolean written;

        boolean notFirst;

        byte[] presetTest;

        // Actual data


        PUKPolicy pukPolicy; // Optional

        public PUKPolicy getPUKPolicy() {
            return pukPolicy;
        }


        boolean userModifiable = true;

        boolean userModifiableSet;

        public boolean getUserModifiable() {
            return userModifiable;
        }

        public PINPolicy setUserModifiable(boolean flag) {
            userModifiable = flag;
            userModifiableSet = true;
            return this;
        }

        boolean userDefined = true;

        public boolean getUserDefinedFlag() {
            return userDefined;
        }


        PassphraseFormat format;

        int minLength;

        int maxLength;

        int retryLimit;

        Grouping grouping; // Optional

        Set<PatternRestriction> patternRestrictions = EnumSet.noneOf(PatternRestriction.class);

        InputMethod inputMethod; // Optional


        String id;

        public String getID() {
            return id;
        }


        private PINPolicy() {
            this.id = pinPrefix + ++nextPinIdSuffix;
            pinPolicies.add(this);
        }

        void writePolicy(JSONObjectWriter wr) throws IOException {
            wr.setString(ID_JSON, id);
            wr.setInt(MIN_LENGTH_JSON, minLength);
            wr.setInt(MAX_LENGTH_JSON, maxLength);
            wr.setInt(RETRY_LIMIT_JSON, retryLimit);
            wr.setString(FORMAT_JSON, format.getProtocolName());
            if (userModifiableSet) {
                wr.setBoolean(USER_MODIFIABLE_JSON, userModifiable);
            }
            if (grouping != null) {
                wr.setString(GROUPING_JSON, grouping.getProtocolName());
            }
            if (inputMethod != null) {
                wr.setString(INPUT_METHOD_JSON, inputMethod.getProtocolName());
            }
            if (!patternRestrictions.isEmpty()) {
                Vector<String> prs = new Vector<String>();
                for (PatternRestriction pr : patternRestrictions) {
                    prs.add(pr.getProtocolName());
                }
                wr.setStringArray(PATTERN_RESTRICTIONS_JSON, prs.toArray(new String[0]));
            }

            MacGenerator pin_policy_mac = new MacGenerator();
            pin_policy_mac.addString(id);
            pin_policy_mac.addString(pukPolicy == null ? SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE : pukPolicy.id);
            pin_policy_mac.addBool(userDefined);
            pin_policy_mac.addBool(userModifiable);
            pin_policy_mac.addByte(format.getSksValue());
            pin_policy_mac.addShort(retryLimit);
            pin_policy_mac.addByte(grouping == null ? Grouping.NONE.getSksValue() : grouping.getSksValue());
            pin_policy_mac.addByte(PatternRestriction.getSksValue(patternRestrictions));
            pin_policy_mac.addShort(minLength);
            pin_policy_mac.addShort(maxLength);
            pin_policy_mac.addByte(inputMethod == null ? InputMethod.ANY.getSksValue() : inputMethod.getSksValue());
            wr.setBinary(MAC_JSON, mac(pin_policy_mac.getResult(), SecureKeyStore.METHOD_CREATE_PIN_POLICY));
        }

        public PINPolicy setInputMethod(InputMethod inputMethod) {
            this.inputMethod = inputMethod;
            return this;
        }

        public PINPolicy setGrouping(Grouping grouping) {
            this.grouping = grouping;
            return this;
        }

        public PINPolicy addPatternRestriction(PatternRestriction pattern) {
            this.patternRestrictions.add(pattern);
            return this;
        }
    }


    public class Key implements Serializable {

        private static final long serialVersionUID = 1L;

        LinkedHashMap<String, ExtensionInterface> extensions = new LinkedHashMap<String, ExtensionInterface>();

        PostProvisioningTargetKey cloneOrUpdateOperation;

        boolean keyInitDone;

        byte[] expectedAttestMacCount;  // Two bytes

        private void addExtension(ExtensionInterface ei) throws IOException {
            if (extensions.put(ei.type, ei) != null) {
                bad("Duplicate extension:" + ei.type);
            }
        }

        public PropertyBag[] getPropertyBags() {
            Vector<PropertyBag> propertyBags = new Vector<PropertyBag>();
            for (ExtensionInterface ei : extensions.values()) {
                if (ei instanceof PropertyBag) {
                    propertyBags.add((PropertyBag) ei);
                }
            }
            return propertyBags.toArray(new PropertyBag[0]);
        }

        public PropertyBag addPropertyBag(String type) throws IOException {
            PropertyBag propertyBag = new PropertyBag(type);
            addExtension(propertyBag);
            return propertyBag;
        }


        Object object;

        public Key setUserObject(Object object) {
            this.object = object;
            return this;
        }

        public Object getUserObject() {
            return object;
        }


        public Key addExtension(String type, byte[] data) throws IOException {
            addExtension(new Extension(type, data));
            return this;
        }

        public Key addEncryptedExtension(String type, byte[] data) throws IOException {
            addExtension(new EncryptedExtension(type, encrypt(data)));
            return this;
        }

        public Key addLogotype(String type, MIMETypedObject logotype) throws IOException {
            addExtension(new Logotype(type, logotype));
            return this;
        }


        X509Certificate[] certificatePath;

        public Key setCertificatePath(X509Certificate[] certificatePath) {
            this.certificatePath = certificatePath;
            return this;
        }

        public X509Certificate[] getCertificatePath() {
            return certificatePath;
        }


        byte[] encryptedSymmetricKey;

        public Key setSymmetricKey(byte[] symmetricKey) throws IOException {
            this.encryptedSymmetricKey = encrypt(symmetricKey);
            return this;
        }

        String[] getSortedAlgorithms(String[] algorithms) throws IOException {
            int i = 0;
            while (true) {
                if (i < (algorithms.length - 1)) {
                    if (algorithms[i].compareTo(algorithms[i + 1]) > 0) {
                        String s = algorithms[i];
                        algorithms[i] = algorithms[i + 1];
                        algorithms[i + 1] = s;
                        i = 0;
                    } else {
                        i++;
                    }
                } else {
                    break;
                }
            }
            return algorithms;
        }

        String[] endorsedAlgorithms;

        public Key setEndorsedAlgorithms(String[] endorsedAlgorithms) throws IOException {
            this.endorsedAlgorithms = getSortedAlgorithms(endorsedAlgorithms);
            return this;
        }


        public byte[] getEncryptedSymmetricKey() {
            return encryptedSymmetricKey;
        }


        byte[] encryptedPrivateKey;

        public Key setPrivateKey(byte[] privateKey) throws IOException {
            this.encryptedPrivateKey = encrypt(privateKey);
            return this;
        }

        public byte[] getEncryptedPrivateKey() {
            return encryptedPrivateKey;
        }


        String friendlyName;

        public Key setFriendlyName(String friendlyName) {
            this.friendlyName = friendlyName;
            return this;
        }

        public String getFriendlyName() {
            return friendlyName;
        }


        PublicKey publicKey;   // Filled in by KeyCreationRequestDecoder

        public PublicKey getPublicKey() {
            return publicKey;
        }


        byte[] attestation;   // Filled in by KeyCreationRequestDecoder

        public byte[] getAttestation() {
            return attestation;
        }


        ExportProtection exportProtection;

        public Key setExportProtection(ExportProtection exportProtection) {
            this.exportProtection = exportProtection;
            return this;
        }

        public ExportProtection getExportPolicy() {
            return exportProtection;
        }


        byte[] serverSeed;

        public Key setServerSeed(byte[] serverSeed) throws IOException {
            if (serverSeed != null && serverSeed.length > SecureKeyStore.MAX_LENGTH_SERVER_SEED) {
                bad("Server seed > " + SecureKeyStore.MAX_LENGTH_SERVER_SEED + " bytes");
            }
            this.serverSeed = serverSeed;
            return this;
        }


        boolean enablePinCaching;
        boolean enablePinCachingSet;

        public Key setEnablePINCaching(boolean flag) {
            enablePinCaching = flag;
            enablePinCachingSet = true;
            return this;
        }

        public boolean getEnablePINCachingFlag() {
            return enablePinCaching;
        }


        boolean trustAnchor;
        boolean trustAnchorSet;

        public Key setTrustAnchor(boolean flag) {
            trustAnchor = flag;
            trustAnchorSet = true;
            return this;
        }

        public boolean getTrustAnchorFlag() {
            return trustAnchor;
        }


        BiometricProtection biometricProtection;

        public Key setBiometricProtection(BiometricProtection biometricProtection) throws IOException {
            // TODO there must be some PIN-related tests here...
            this.biometricProtection = biometricProtection;
            return this;
        }


        public BiometricProtection getBiometricProtection() {
            return biometricProtection;
        }


        DeleteProtection deleteProtection;

        public Key setDeleteProtection(DeleteProtection deleteProtection) throws IOException {
            // TODO there must be some PIN-related tests here...
            this.deleteProtection = deleteProtection;
            return this;
        }

        public DeleteProtection getDeletePolicy() {
            return deleteProtection;
        }


        String id;

        public String getID() {
            return id;
        }

        public Key setID(String newId) throws IOException {
            requestedKeys.remove(id);
            id = KeyGen2Validator.validateID(ID_JSON, newId);
            return addKeyToRequestList(this);
        }


        AppUsage appUsage;

        public AppUsage getAppUsage() {
            return appUsage;
        }

        KeySpecifier keySpecifier;

        PINPolicy pinPolicy;

        public PINPolicy getPINPolicy() {
            return pinPolicy;
        }


        byte[] presetPin;

        public byte[] getEncryptedPIN() {
            return presetPin;
        }


        boolean devicePinProtection;

        public boolean getDevicePINProtection() {
            return devicePinProtection;
        }


        void setPostOp(PostProvisioningTargetKey op) throws IOException {
            if (cloneOrUpdateOperation != null) {
                bad("Clone or Update already set for this key");
            }
            if (pinPolicy != null || devicePinProtection) {
                bad("Clone/Update keys cannot be PIN protected");
            }
            cloneOrUpdateOperation = op;
        }


        public Key setClonedKeyProtection(String oldClientSessionId,
                                          String oldServerSessionId,
                                          X509Certificate oldKey,
                                          PublicKey keyManagementKey) throws IOException {
            PostProvisioningTargetKey op = addPostOperation(oldClientSessionId,
                                                            oldServerSessionId,
                                                            oldKey,
                                                            PostOperation.CLONE_KEY_PROTECTION,
                                                            keyManagementKey);
            setPostOp(op);
            return this;
        }

        public Key setUpdatedKey(String oldClientSessionId,
                                 String oldServerSessionId,
                                 X509Certificate oldKey,
                                 PublicKey keyManagementKey) throws IOException {
            PostProvisioningTargetKey op = addPostOperation(oldClientSessionId,
                                                            oldServerSessionId,
                                                            oldKey,
                                                            PostOperation.UPDATE_KEY,
                                                            keyManagementKey);
            setPostOp(op);
            return this;
        }

        Key(AppUsage appUsage,
            KeySpecifier keySpecifier,
            PINPolicy pinPolicy,
            byte[] presetPin,
            boolean devicePinProtection) throws IOException {
            this.id = keyPrefix + ++nextKeyIdSuffix;
            this.appUsage = appUsage;
            this.keySpecifier = keySpecifier;
            this.pinPolicy = pinPolicy;
            this.presetPin = presetPin;
            this.devicePinProtection = devicePinProtection;
            if (pinPolicy != null) {
                if (pinPolicy.notFirst) {
                    if (pinPolicy.grouping == Grouping.SHARED && ((pinPolicy.presetTest == null && presetPin != null) || (pinPolicy.presetTest != null && presetPin == null))) {
                        bad("\"shared\" PIN keys must either have no \"presetPin\" " + "value or all be preset");
                    }
                } else {
                    pinPolicy.notFirst = true;
                    pinPolicy.presetTest = presetPin;
                }
            }
        }

        void writeRequest(JSONObjectWriter wr) throws IOException {
            keyInitDone = true;
            MacGenerator keyPairMac = new MacGenerator();
            keyPairMac.addString(id);
            keyPairMac.addString(keyAttestationAlgorithm);
            keyPairMac.addArray(serverSeed == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : serverSeed);
            keyPairMac.addString(pinPolicy == null ?
                    SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE
                    :
                    pinPolicy.id);
            if (getEncryptedPIN() == null) {
                keyPairMac.addString(SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE);
            } else {
                keyPairMac.addArray(getEncryptedPIN());
            }
            keyPairMac.addBool(devicePinProtection);
            keyPairMac.addBool(enablePinCaching);
            keyPairMac.addByte(biometricProtection == null ?
                    BiometricProtection.NONE.getSksValue() : biometricProtection.getSksValue());
            keyPairMac.addByte(exportProtection == null ?
                    ExportProtection.NON_EXPORTABLE.getSksValue() : exportProtection.getSksValue());
            keyPairMac.addByte(deleteProtection == null ?
                    DeleteProtection.NONE.getSksValue() : deleteProtection.getSksValue());
            keyPairMac.addByte(appUsage.getSksValue());
            keyPairMac.addString(friendlyName == null ? "" : friendlyName);
            keyPairMac.addString(keySpecifier.getKeyAlgorithm().getAlgorithmId(AlgorithmPreferences.SKS));
            keyPairMac.addArray(keySpecifier.getKeyParameters() == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : keySpecifier.getKeyParameters());
            if (endorsedAlgorithms != null) for (String algorithm : endorsedAlgorithms) {
                keyPairMac.addString(algorithm);
            }

            wr.setString(ID_JSON, id);

            if (serverSeed != null) {
                wr.setBinary(SERVER_SEED_JSON, serverSeed);
            }

            if (devicePinProtection) {
                wr.setBoolean(DEVICE_PIN_PROTECTION_JSON, true);
            }

            if (presetPin != null) {
                wr.setBinary(ENCRYPTED_PIN_JSON, presetPin);
            }

            if (enablePinCachingSet) {
                if (enablePinCaching && (pinPolicy == null || pinPolicy.inputMethod != InputMethod.TRUSTED_GUI)) {
                    bad("\"" + ENABLE_PIN_CACHING_JSON + "\" must be combined with " + InputMethod.TRUSTED_GUI.toString());
                }
                wr.setBoolean(ENABLE_PIN_CACHING_JSON, enablePinCaching);
            }

            if (biometricProtection != null) {
                wr.setString(BIOMETRIC_PROTECTION_JSON, biometricProtection.getProtocolName());
            }

            if (exportProtection != null) {
                wr.setString(EXPORT_PROTECTION_JSON, exportProtection.getProtocolName());
            }

            if (deleteProtection != null) {
                wr.setString(DELETE_PROTECTION_JSON, deleteProtection.getProtocolName());
            }

            if (friendlyName != null) {
                wr.setString(FRIENDLY_NAME_JSON, friendlyName);
            }

            wr.setString(APP_USAGE_JSON, appUsage.getProtocolName());

            wr.setString(KEY_ALGORITHM_JSON, keySpecifier.getKeyAlgorithm().getAlgorithmId(AlgorithmPreferences.SKS));
            if (keySpecifier.getKeyParameters() != null) {
                wr.setBinary(KEY_PARAMETERS_JSON, keySpecifier.getKeyParameters());
            }

            if (endorsedAlgorithms != null && endorsedAlgorithms.length > 0) {
                wr.setStringArray(ENDORSED_ALGORITHMS_JSON, endorsedAlgorithms);
            }

            wr.setBinary(MAC_JSON, mac(keyPairMac.getResult(), SecureKeyStore.METHOD_CREATE_KEY_ENTRY));

            expectedAttestMacCount = getMacSequenceCounterAndUpdate();
        }
    }

    public Key[] getKeys() {
        return requestedKeys.values().toArray(new Key[0]);
    }

    public ProtocolPhase getProtocolPhase() {
        return currentPhase;
    }

    ServerCryptoInterface serverCryptoInterface;

    enum CAPABILITY {UNDEFINED, URI_FEATURE, VALUES, IMAGE_ATTRIBUTES}

    LinkedHashMap<String, CAPABILITY> queriedCapabilities = new LinkedHashMap<String, CAPABILITY>();

    static abstract class CapabilityBase implements Serializable {

        private static final long serialVersionUID = 1L;

        String type;

        CAPABILITY capability = CAPABILITY.URI_FEATURE;

        boolean supported = true;

        public String getType() {
            return type;
        }

        boolean isSupported() {
            return supported;
        }
    }

    public static class ImagePreference extends CapabilityBase {

        private static final long serialVersionUID = 1L;

        String mimeType;
        int width;
        int height;

        ImagePreference(String mimeType, int width, int height) {
            this.mimeType = mimeType;
            this.width = width;
            this.height = height;
            super.capability = CAPABILITY.IMAGE_ATTRIBUTES;
        }

        public String getMimeType() {
            return mimeType;
        }

        public int getWidth() {
            return width;
        }

        public int getHeight() {
            return height;
        }
    }

    static class Values extends CapabilityBase {

        private static final long serialVersionUID = 1L;

        String[] values;

        Values(String[] values) {

            this.values = values;
            super.capability = CAPABILITY.VALUES;
        }

        public String[] getValues() {
            return values;
        }
    }

    static class Feature extends CapabilityBase {

        private static final long serialVersionUID = 1L;

        Feature(boolean supported) {
            this.supported = supported;
        }
    }

    LinkedHashMap<String, CapabilityBase> receivedCapabilities;

    CapabilityBase getCapability(String typeUri, CAPABILITY what) throws IOException {
        CapabilityBase capability = receivedCapabilities.get(typeUri);
        if (capability != null && capability.isSupported()) {
            if (capability.capability != what) {
                bad("Type error for capability: " + typeUri);
            }
            return capability;
        }
        return null;
    }

    public ImagePreference getImagePreference(String imageTypeUri) throws IOException {
        return (ImagePreference) getCapability(imageTypeUri, CAPABILITY.IMAGE_ATTRIBUTES);
    }

    public String[] getValuesCapability(String valuesTypeUri) throws IOException {
        Values values = (Values) getCapability(valuesTypeUri, CAPABILITY.VALUES);
        return values == null ? null : values.getValues();
    }

    public boolean isFeatureSupported(String featureTypeUri) throws IOException {
        return getCapability(featureTypeUri, CAPABILITY.URI_FEATURE) != null;
    }

    ProtocolPhase currentPhase = ProtocolPhase.INVOCATION;

    boolean requestPhase = true;

    int next_personal_code = 1;

    String keyPrefix = "Key.";

    int nextKeyIdSuffix = 0;

    String pinPrefix = "PIN.";

    int nextPinIdSuffix = 0;

    String pukPrefix = "PUK.";

    int nextPukIdSuffix = 0;

    short macSequenceCounter;

    LinkedHashMap<String, Key> requestedKeys = new LinkedHashMap<String, Key>();

    String serverSessionId;

    String clientSessionId;

    String issuerUri;

    int sessionLifeTime;

    short sessionKeyLimit;

    String provisioningSessionAlgorithm = SecureKeyStore.ALGORITHM_SESSION_ATTEST_1;

    String keyAttestationAlgorithm;

    ECPublicKey serverEphemeralKey;

    ECPublicKey clientEphemeralKey;

    PublicKey keyManagementKey;
    
    String serverTime;

    byte[] savedCloseNonce;

    X509Certificate[] deviceCertificatePath;

    PostProvisioningTargetKey addPostOperation(String oldClientSessionId,
                                               String oldServerSessionId,
                                               X509Certificate oldKey,
                                               PostOperation operation,
                                               PublicKey keyManagementKey) throws IOException {
        try {
            PostProvisioningTargetKey newPostOp = new PostProvisioningTargetKey(oldClientSessionId,
                                                                                oldServerSessionId,
                                                                                oldKey.getEncoded(),
                                                                                keyManagementKey,
                                                                                operation);
            for (PostProvisioningTargetKey postOp : postOperations) {
                if (postOp.matching(newPostOp)) {
                    if (postOp.postOperation == PostOperation.DELETE_KEY || 
                            newPostOp.postOperation == PostOperation.DELETE_KEY) {
                        bad("DeleteKey cannot be combined with other management operations");
                    }
                    if (postOp.postOperation == PostOperation.UPDATE_KEY ||
                            newPostOp.postOperation == PostOperation.UPDATE_KEY) {
                        bad("UpdateKey can only be performed once per key");
                    }
                }
            }
            postOperations.add(newPostOp);
            return newPostOp;
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    void checkSession(String clientSessionId, String serverSessionId) throws IOException {
        if (!this.clientSessionId.equals(clientSessionId) || !this.serverSessionId.equals(serverSessionId)) {
            bad("Session ID mismatch");
        }
    }

    private byte[] getMacSequenceCounterAndUpdate() {
        int q = macSequenceCounter++;
        return new byte[]{(byte) (q >>> 8), (byte) (q & 0xFF)};
    }

    byte[] mac(byte[] data, byte[] method) throws IOException {
        return serverCryptoInterface.mac(data, ArrayUtil.add(method, getMacSequenceCounterAndUpdate()));
    }

    byte[] attest(byte[] data, byte[] macCounter) throws IOException {
        return serverCryptoInterface.mac(data, ArrayUtil.add(SecureKeyStore.KDF_DEVICE_ATTESTATION, macCounter));
    }

    byte[] encrypt(byte[] data) throws IOException {
        return serverCryptoInterface.encrypt(data);
    }

    void checkFinalResult(byte[] closeSessionAttestation) throws IOException, GeneralSecurityException {
        MacGenerator check = new MacGenerator();
        check.addArray(savedCloseNonce);
        if (!ArrayUtil.compare(attest(check.getResult(), getMacSequenceCounterAndUpdate()), closeSessionAttestation)) {
            bad("Final attestation failed!");
        }
    }

    static void bad(String message) throws IOException {
        throw new IOException(message);
    }

    boolean privacyEnabled;
    boolean privacyEnabledSet;

    public void setPrivacyEnabled(boolean flag) throws IOException {
        if (!requestPhase || currentPhase != ProtocolPhase.INVOCATION) {
            throw new IOException("Must be specified before any requests");
        }
        privacyEnabledSet = true;
        privacyEnabled = flag;
    }


    KeyAlgorithms ephemeraKeyAlgorithm = KeyAlgorithms.NIST_P_256;

    public void setEphemeralKeyAlgorithm(KeyAlgorithms ephemeralKeyAlgorithm) {
        this.ephemeraKeyAlgorithm = ephemeralKeyAlgorithm;
    }


    String[] languageList;

    public void setPreferredLanguages(String[] optionalLanguageList) {
        this.languageList = optionalLanguageList;
    }


    String[] keyContainerList;

    public void setTargetKeyContainerList(KeyContainerTypes[] optionalKeyContainerList) throws IOException {
        this.keyContainerList = KeyContainerTypes.parseOptionalKeyContainerList(optionalKeyContainerList);
    }


    // Constructor
    public ServerState(ServerCryptoInterface serverCryptoInterface, String issuerUri) {
        this.serverCryptoInterface = serverCryptoInterface;
        this.issuerUri = issuerUri;
        serverTime = ISODateTime.formatDateTime(new GregorianCalendar(), ISODateTime.UTC_NO_SUBSECONDS);
    }

    ServerState addQuery(String typeUri, CAPABILITY what) throws IOException {
        CAPABILITY existing = queriedCapabilities.get(typeUri);
        if (existing != null) {
            throw new IOException("Duplicate request URI: " + typeUri);
        }
        queriedCapabilities.put(typeUri, what);
        return this;
    }

    public ServerState addFeatureQuery(String featureTypeUri) throws IOException {
        return addQuery(featureTypeUri, CAPABILITY.URI_FEATURE);
    }

    public ServerState addValuesQuery(String valuesTypeUri) throws IOException {
        return addQuery(valuesTypeUri, CAPABILITY.VALUES);
    }

    public ServerState addImageAttributesQuery(String imageTypeUri) throws IOException {
        return addQuery(imageTypeUri, CAPABILITY.IMAGE_ATTRIBUTES);
    }

    void checkState(boolean request, ProtocolPhase expected) throws IOException {
        if (request ^ requestPhase) {
            throw new IOException("Wrong order of request versus response");
        }
        requestPhase = !requestPhase;
        if (currentPhase != expected) {
            throw new IOException("Incorrect object, expected: " + expected + " got: " + currentPhase);
        }
    }


    public void update(InvocationResponseDecoder invocationResponse) throws IOException {
        checkState(false, ProtocolPhase.INVOCATION);
        currentPhase = ProtocolPhase.PROVISIONING_INITIALIZATION;
        if (queriedCapabilities.size() != invocationResponse.receivedCapabilities.size()) {
            bad("Differing length of queried versus received capabilities");
        }
        receivedCapabilities = invocationResponse.receivedCapabilities;
        for (String capability : queriedCapabilities.keySet()) {
            CAPABILITY queried = queriedCapabilities.get(capability);
            CapabilityBase received = receivedCapabilities.get(capability);
            if (received == null) {
                bad("Missing capability: " + capability);
            }
            if (received.supported && queried != received.capability) {
                bad("Non-matching capability for URI: " + capability);
            }
        }
    }


    public void update(ProvisioningInitializationResponseDecoder provisioningInitializationResponse, 
                       X509Certificate serverCertificate) throws IOException {
        try {
            checkState(false, ProtocolPhase.PROVISIONING_INITIALIZATION);
            clientSessionId = provisioningInitializationResponse.clientSessionId;
            deviceCertificatePath = provisioningInitializationResponse.deviceCertificatePath;
            clientEphemeralKey = provisioningInitializationResponse.clientEphemeralKey;
            if (!serverTime.equals(provisioningInitializationResponse.serverTime)) {
                bad("Received \"" + KeyGen2Constants.SERVER_TIME_JSON + "\" mismatch");
            }

            MacGenerator kdf = new MacGenerator();
            kdf.addString(clientSessionId);
            kdf.addString(serverSessionId);
            kdf.addString(issuerUri);
            kdf.addArray(getDeviceID());

            MacGenerator attestationArguments = new MacGenerator();
            attestationArguments.addString(clientSessionId);
            attestationArguments.addString(serverSessionId);
            attestationArguments.addString(issuerUri);
            attestationArguments.addArray(getDeviceID());
            attestationArguments.addString(provisioningSessionAlgorithm);
            attestationArguments.addBool(getDeviceCertificate() == null);
            attestationArguments.addArray(serverEphemeralKey.getEncoded());
            attestationArguments.addArray(clientEphemeralKey.getEncoded());
            attestationArguments.addArray(keyManagementKey == null ? new byte[0] : keyManagementKey.getEncoded());
            attestationArguments.addInt((int) (provisioningInitializationResponse.clientTime.getTimeInMillis() / 1000));
            attestationArguments.addInt(sessionLifeTime);
            attestationArguments.addShort(sessionKeyLimit);

            serverCryptoInterface.generateAndVerifySessionKey(clientEphemeralKey,
                                                              kdf.getResult(),
                                                              attestationArguments.getResult(),
                                                              getDeviceCertificate(),
                                                              provisioningInitializationResponse.attestation);
            if (((serverCertificate == null ^ provisioningInitializationResponse.serverCertificateFingerprint == null)) ||
                (serverCertificate != null && !ArrayUtil.compare(provisioningInitializationResponse.serverCertificateFingerprint,
                    HashAlgorithms.SHA256.digest(serverCertificate.getEncoded())))) {
                bad("Attribute '" + SERVER_CERT_FP_JSON + "' is missing or is invalid");
            }
            provisioningInitializationResponse.signature.verify(new JSONSymKeyVerifier(new SymKeyVerifierInterface() {
                @Override
                public boolean verifyData(byte[] data, byte[] digest, MACAlgorithms algorithm, String keyId) throws IOException {
                    return ArrayUtil.compare(serverCryptoInterface.mac(data, SecureKeyStore.KDF_EXTERNAL_SIGNATURE), digest);
                }
            }));
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
        currentPhase = ProtocolPhase.CREDENTIAL_DISCOVERY;
    }


    byte[] getDeviceID() throws GeneralSecurityException {
        return getDeviceCertificate() == null ? SecureKeyStore.KDF_ANONYMOUS : getDeviceCertificate().getEncoded();
    }

    public void update(CredentialDiscoveryResponseDecoder credentialDiscoveryResponse) throws IOException {
        checkState(false, ProtocolPhase.CREDENTIAL_DISCOVERY);
        checkSession(credentialDiscoveryResponse.clientSessionId,
                     credentialDiscoveryResponse.serverSessionId);
        currentPhase = ProtocolPhase.KEY_CREATION;
    }


    public void update(KeyCreationResponseDecoder keyCreationResponse) throws IOException {
        checkState(false, ProtocolPhase.KEY_CREATION);
        checkSession(keyCreationResponse.clientSessionId,
                     keyCreationResponse.serverSessionId);
        if (keyCreationResponse.generatedKeys.size() != requestedKeys.size()) {
            ServerState.bad("Different number of requested and received keys");
        }
        Iterator<ServerState.Key> req_key_iterator = requestedKeys.values().iterator();
        for (KeyCreationResponseDecoder.GeneratedPublicKey gpk : keyCreationResponse.generatedKeys.values()) {
            ServerState.Key kp = req_key_iterator.next();
            if (!kp.id.equals(gpk.id)) {
                ServerState.bad("Wrong ID order:" + gpk.id + " / " + kp.id);
            }
            if (kp.keySpecifier.keyAlgorithm != KeyAlgorithms.getKeyAlgorithm(kp.publicKey = gpk.publicKey, kp.keySpecifier.keyParameters != null)) {
                ServerState.bad("Wrong key type returned for key id:" + gpk.id);
            }
            MacGenerator attestation = new MacGenerator();
            // Write key attestation data
            attestation.addString(gpk.id);
            attestation.addArray(gpk.publicKey.getEncoded());
            if (!ArrayUtil.compare(attest(attestation.getResult(), kp.expectedAttestMacCount), 
                                   kp.attestation = gpk.attestation)) {
                ServerState.bad("Attestation failed for key id:" + gpk.id);
            }
        }
        currentPhase = ProtocolPhase.PROVISIONING_FINALIZATION;
    }


    public void update(ProvisioningFinalizationResponseDecoder provisioningFinalizationResponse) throws IOException {
        checkState(false, ProtocolPhase.PROVISIONING_FINALIZATION);
        checkSession(provisioningFinalizationResponse.clientSessionId,
                     provisioningFinalizationResponse.serverSessionId);
        try {
            checkFinalResult(provisioningFinalizationResponse.attestation);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
        currentPhase = ProtocolPhase.DONE;
    }

    public X509Certificate getDeviceCertificate() {
        return deviceCertificatePath == null ? null : deviceCertificatePath[0];
    }

    public String getDeviceIDString(boolean longVersion) {
        return DeviceID.getDeviceId(getDeviceCertificate(), longVersion);
    }


    public X509Certificate[] getDeviceCertificatePath() {
        return deviceCertificatePath;
    }


    public void addPostDeleteKey(String oldClientSessionId,
                                 String oldServerSessionId,
                                 X509Certificate oldKey,
                                 PublicKey keyManagementKey) throws IOException {
        addPostOperation(oldClientSessionId,
                         oldServerSessionId,
                         oldKey,
                         PostOperation.DELETE_KEY,
                         keyManagementKey);
    }


    public void addPostUnlockKey(String oldClientSessionId,
                                 String oldServerSessionId,
                                 X509Certificate oldKey,
                                 PublicKey keyManagementKey) throws IOException {
        addPostOperation(oldClientSessionId,
                         oldServerSessionId,
                         oldKey,
                         PostOperation.UNLOCK_KEY,
                         keyManagementKey);
    }


    public String getClientSessionId() {
        return clientSessionId;
    }

    public String getServerSessionId() {
        return serverSessionId;
    }

    Vector<PINPolicy> pinPolicies = new Vector<PINPolicy>();

    public PINPolicy createPINPolicy(PassphraseFormat format, 
                                     int minLength,
                                     int maxLength,
                                     int retryLimit,
                                     PUKPolicy pukPolicy) throws IOException {
        PINPolicy pinPolicy = new PINPolicy();
        pinPolicy.format = format;
        pinPolicy.minLength = minLength;
        pinPolicy.maxLength = maxLength;
        pinPolicy.retryLimit = retryLimit;
        pinPolicy.pukPolicy = pukPolicy;
        if (format == null) {
            bad("PassphraseFormat must not be null");
        }
        if (minLength > maxLength) {
            bad("minLength > maxLength");
        }
        return pinPolicy;
    }

    Vector<PUKPolicy> pukPolicies = new Vector<PUKPolicy>();

    public PUKPolicy createPUKPolicy(byte[] puk, PassphraseFormat format, int retryLimit) throws IOException {
        return new PUKPolicy(encrypt(puk), format, retryLimit);
    }

    private Key addKeyToRequestList(Key key) throws IOException {
        if (key.keyInitDone) {
            bad("Can't initialize key at this [late] stage");
        }
        if (requestedKeys.put(key.getID(), key) != null) {
            bad("Duplicate definition: " + key.getID());
        }
        return key;
    }

    private Key addKeyProperties(AppUsage appUsage,
                                 KeySpecifier keySpecifier,
                                 PINPolicy pinPolicy,
                                 byte[] presetPin,
                                 boolean devicePinProtection) throws IOException {
        return addKeyToRequestList(new Key(appUsage, keySpecifier, pinPolicy, presetPin, devicePinProtection));
    }


    public Key createKeyWithPresetPIN(AppUsage appUsage, 
                                      KeySpecifier keySpecifier,
                                      PINPolicy pinPolicy,
                                      byte[] pin) throws IOException {
        if (pinPolicy == null) {
            bad("PresetPIN without PINPolicy is not allowed");
        }
        pinPolicy.userDefined = false;
        return addKeyProperties(appUsage, keySpecifier, pinPolicy, encrypt(pin), false);
    }


    public Key createKey(AppUsage appUsage,
                         KeySpecifier keySpecifier,
                         PINPolicy pinPolicy) throws IOException {
        return addKeyProperties(appUsage, keySpecifier, pinPolicy, null, false);
    }


    public Key createDevicePINProtectedKey(AppUsage appUsage,
                                           KeySpecifier keySpecifier) throws IOException {
        return addKeyProperties(appUsage, keySpecifier, null, null, true);
    }


    private LinkedHashMap<String, Object> serviceSpecificObjects = new LinkedHashMap<String, Object>();

    public void setServiceSpecificObject(String name, Object value) {
        serviceSpecificObjects.put(name, value);
    }


    public Object getServiceSpecificObject(String name) {
        return serviceSpecificObjects.get(name);
    }


    public ECPublicKey generateEphemeralKey() throws IOException {
        return serverCryptoInterface.generateEphemeralKey(ephemeraKeyAlgorithm);
    }
}
