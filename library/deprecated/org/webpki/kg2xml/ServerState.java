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

import static org.webpki.kg2xml.KeyGen2Constants.*;

import java.io.IOException;
import java.io.Serializable;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.Vector;

import org.webpki.crypto.DeviceID;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeyVerifierInterface;

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
import org.webpki.util.MimeTypedObject;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSymKeyVerifier;

public class ServerState implements Serializable
  {
    private static final long serialVersionUID = 1L;
    
    public enum ProtocolPhase {PLATFORM_NEGOTIATION,
                               PROVISIONING_INITIALIZATION,
                               CREDENTIAL_DISCOVERY,
                               KEY_CREATION,
                               PROVISIONING_FINALIZATION,
                               DONE};

    enum PostOperation
      {
        DELETE_KEY            (SecureKeyStore.METHOD_POST_DELETE_KEY,           DELETE_KEY_ELEM), 
        UNLOCK_KEY            (SecureKeyStore.METHOD_POST_UNLOCK_KEY,           UNLOCK_KEY_ELEM), 
        UPDATE_KEY            (SecureKeyStore.METHOD_POST_UPDATE_KEY,           UPDATE_KEY_ELEM), 
        CLONE_KEY_PROTECTION  (SecureKeyStore.METHOD_POST_CLONE_KEY_PROTECTION, CLONE_KEY_PROTECTION_ELEM);
        
        private byte[] method;
        
        private String xml_elem;
        
        PostOperation (byte[] method, String xml_elem)
          {
            this.method = method;
            this.xml_elem = xml_elem;
          }

        byte[] getMethod ()
          {
            return method;
          }
        
        String getXMLElem ()
          {
            return xml_elem;
          }
      }
    
    class PostProvisioningTargetKey implements Serializable
      {
        private static final long serialVersionUID = 1L;
        
        String clientSessionId;
        
        String serverSessionId;
        
        PublicKey keyManagementKey;
      
        byte[] certificate_data;
        
        PostOperation postOperation;
        
        PostProvisioningTargetKey (String clientSessionId,
                                   String serverSessionId,
                                   byte[] certificate_data,
                                   PublicKey keyManagementKey,
                                   PostOperation postOperation)
          {
            this.clientSessionId = clientSessionId;
            this.serverSessionId = serverSessionId;
            this.certificate_data = certificate_data;
            this.keyManagementKey = keyManagementKey;
            this.postOperation = postOperation;
          }
  
        public boolean equals (Object o)
          {
            return o instanceof PostProvisioningTargetKey && 
                   clientSessionId.equals(((PostProvisioningTargetKey)o).clientSessionId) &&
                   serverSessionId.equals (((PostProvisioningTargetKey)o).serverSessionId) &&
                   ArrayUtil.compare (certificate_data, ((PostProvisioningTargetKey)o).certificate_data);
          }
      }
  
    Vector<PostProvisioningTargetKey> post_operations = new Vector<PostProvisioningTargetKey> ();
  
    public abstract class ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String type;
        
        public String getType ()
          {
            return type;
          }
        
        public abstract byte getSubType ();
        
        public String getQualifier () throws IOException
          {
            return "";
          }
        
        public abstract byte[] getExtensionData () throws IOException;
        
        abstract void writeExtension (DOMWriterHelper wr, byte[] macData) throws IOException;
        
        void writeCore (DOMWriterHelper wr, byte[] macData) throws IOException
          {
            wr.setBinaryAttribute (MAC_ATTR, macData);
            wr.setStringAttribute (TYPE_ATTR, type);
          }
        
        ExtensionInterface (String type)
          {
            this.type = type;
          }
      }

    public class Extension extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        byte[] data;

        Extension (String type, byte[] data)
          {
            super (type);
            this.data = data;
          }

        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_EXTENSION;
          }

        public byte[] getExtensionData () throws IOException
          {
            return data;
          }

        void writeExtension (DOMWriterHelper wr, byte[] macData) throws IOException
          {
            wr.addBinary (EXTENSION_ELEM, data);
            writeCore (wr, macData);
          }
      }

    public class EncryptedExtension extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        byte[] encryptedData;

        EncryptedExtension (String type, byte[] encryptedData)
          {
            super (type);
            this.encryptedData = encryptedData;
          }

        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION;
          }

        public byte[] getExtensionData () throws IOException
          {
            return encryptedData;
          }

        void writeExtension (DOMWriterHelper wr, byte[] macData) throws IOException
          {
            wr.addBinary (ENCRYPTED_EXTENSION_ELEM, encryptedData);
            writeCore (wr, macData);
          }
      }

    public class Logotype extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        MimeTypedObject logotype;

        Logotype (String type, MimeTypedObject logotype)
          {
            super (type);
            this.logotype = logotype;
          }

        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_LOGOTYPE;
          }

        public byte[] getExtensionData () throws IOException
          {
            return logotype.getData ();
          }

        public String getQualifier () throws IOException
          {
            return logotype.getMimeType ();
          }

        void writeExtension (DOMWriterHelper wr, byte[] macData) throws IOException
          {
            wr.addBinary (LOGOTYPE_ELEM, logotype.getData ());
            writeCore (wr, macData);
            wr.setStringAttribute (MIME_TYPE_ATTR, logotype.getMimeType ());
          }
      }

    public class Property implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String name;

        String value;

        boolean writable;
        
        private Property () {}
        
        public String getName ()
          {
            return name;
          }
        
        public String getValue ()
          {
            return value;
          }
        
        public boolean isWritable ()
          {
            return writable;
          }
      }

    public class PropertyBag extends ExtensionInterface implements Serializable
      {
        private static final long serialVersionUID = 1L;

        LinkedHashMap<String,Property> properties = new LinkedHashMap<String,Property> ();

        public PropertyBag addProperty (String name, String value, boolean writable) throws IOException
          {
            Property property = new Property ();
            property.name = name;
            property.value = value;
            property.writable = writable;
            if (properties.put (name, property) != null)
              {
                throw new IOException ("Duplicate property name \"" + name + "\" not allowed");
              }
            return this;
          }

        PropertyBag (String type)
          {
            super (type);
          }
        
        public byte getSubType ()
          {
            return SecureKeyStore.SUB_TYPE_PROPERTY_BAG;
          }
        
        public byte[] getExtensionData () throws IOException
          {
            MacGenerator convert = new MacGenerator ();
            for (Property prop : properties.values ())
              {
                convert.addString (prop.name);
                convert.addBool (prop.writable);
                convert.addString (prop.value);
               }
            return convert.getResult ();
          }
        
        public Property[] getProperties ()
          {
            return properties.values ().toArray (new Property[0]);
          }

        void writeExtension (DOMWriterHelper wr, byte[] macData) throws IOException
          {
            if (properties.isEmpty ())
              {
                throw new IOException ("Empty " + PROPERTY_BAG_ELEM + ": " + type);
              }
            wr.addChildElement (PROPERTY_BAG_ELEM);
            writeCore (wr, macData);
            for (Property property : properties.values ())
              {
                wr.addChildElement (PROPERTY_ELEM);
                wr.setStringAttribute (NAME_ATTR, property.name);
                wr.setStringAttribute (VALUE_ATTR, property.value);
                if (property.writable)
                  {
                    wr.setBooleanAttribute (WRITABLE_ATTR, property.writable);
                  }
                wr.getParent ();
              }
            wr.getParent ();
          }
      }


    public class PUKPolicy implements Serializable
      {
        private static final long serialVersionUID = 1L;

        String id;
        
        byte[] encryptedValue;

        public String getID ()
          {
            return id;
          }

        PassphraseFormat format;

        int retryLimit;

        PUKPolicy (byte[] encryptedValue, PassphraseFormat format, int retryLimit) throws IOException
          {
            this.encryptedValue = encryptedValue;
            this.id = puk_prefix + ++next_puk_id_suffix;
            this.format = format;
            this.retryLimit = retryLimit;
          }

        void writePolicy (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (PUK_POLICY_SPECIFIER_ELEM);

            wr.setStringAttribute (ID_ATTR, id);
            wr.setIntAttribute (RETRY_LIMIT_ATTR, retryLimit);
            wr.setStringAttribute (FORMAT_ATTR, format.getProtocolName ());
            wr.setBinaryAttribute (ENCRYPTED_PUK_ATTR, encryptedValue);

            MacGenerator puk_policy_mac = new MacGenerator ();
            puk_policy_mac.addString (id);
            puk_policy_mac.addArray (encryptedValue);
            puk_policy_mac.addByte (format.getSksValue ());
            puk_policy_mac.addShort (retryLimit);
            wr.setBinaryAttribute (MAC_ATTR, mac (puk_policy_mac.getResult (), SecureKeyStore.METHOD_CREATE_PUK_POLICY));
          }
      }


    public class PINPolicy implements Serializable
      {
        private static final long serialVersionUID = 1L;

        boolean written;

        boolean not_first;

        byte[] preset_test;

        // Actual data


        PUKPolicy pukPolicy; // Optional
        
        public PUKPolicy getPUKPolicy ()
          {
            return pukPolicy;
          }


        boolean userModifiable = true;
        
        boolean user_modifiable_set;
        
        public boolean getUserModifiable ()
          {
            return userModifiable;
          }

        public PINPolicy setUserModifiable (boolean flag)
          {
            userModifiable = flag;
            user_modifiable_set = true;
            return this;
          }
        
        boolean userDefined = true;
        
        public boolean getUserDefinedFlag ()
          {
            return userDefined;
          }


        PassphraseFormat format;

        int minLength;

        int maxLength;

        int retryLimit;

        Grouping grouping; // Optional

        Set<PatternRestriction> patternRestrictions = EnumSet.noneOf (PatternRestriction.class);

        InputMethod inputMethod; // Optional


        String id;
        
        public String getID ()
          {
            return id;
          }


        private PINPolicy ()
          {
            this.id = pin_prefix + ++next_pin_id_suffix;
          }

        void writePolicy (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (PIN_POLICY_SPECIFIER_ELEM);
            wr.setStringAttribute (ID_ATTR, id);
            wr.setIntAttribute (MAX_LENGTH_ATTR, maxLength);
            wr.setIntAttribute (MIN_LENGTH_ATTR, minLength);
            wr.setIntAttribute (RETRY_LIMIT_ATTR, retryLimit);
            if (user_modifiable_set)
              {
                wr.setBooleanAttribute (USER_MODIFIABLE_ATTR, userModifiable);
              }
            if (grouping != null)
              {
                wr.setStringAttribute (GROUPING_ATTR, grouping.getProtocolName ());
              }
            wr.setStringAttribute (FORMAT_ATTR, format.getProtocolName ());
            if (!patternRestrictions.isEmpty ())
              {
                Vector<String> prs = new Vector<String> ();
                for (PatternRestriction pr : patternRestrictions)
                  {
                    prs.add (pr.getProtocolName ());
                  }
                wr.setListAttribute (PATTERN_RESTRICTIONS_ATTR, prs.toArray (new String[0]));
              }
            if (inputMethod != null)
              {
                wr.setStringAttribute (INPUT_METHOD_ATTR, inputMethod.getProtocolName ());
              }

            MacGenerator pin_policy_mac = new MacGenerator ();
            pin_policy_mac.addString (id);
            pin_policy_mac.addString (pukPolicy == null ? SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE : pukPolicy.id);
            pin_policy_mac.addBool (userDefined);
            pin_policy_mac.addBool (userModifiable);
            pin_policy_mac.addByte (format.getSksValue ());
            pin_policy_mac.addShort (retryLimit);
            pin_policy_mac.addByte (grouping == null ? Grouping.NONE.getSksValue () : grouping.getSksValue ());
            pin_policy_mac.addByte (PatternRestriction.getSksValue (patternRestrictions));
            pin_policy_mac.addShort (minLength);
            pin_policy_mac.addShort (maxLength);
            pin_policy_mac.addByte (inputMethod == null ? InputMethod.ANY.getSksValue () : inputMethod.getSksValue ());
            wr.setBinaryAttribute (MAC_ATTR, mac (pin_policy_mac.getResult (), SecureKeyStore.METHOD_CREATE_PIN_POLICY));
          }

        public PINPolicy setInputMethod (InputMethod inputMethod)
          {
            this.inputMethod = inputMethod;
            return this;
          }

        public PINPolicy setGrouping (Grouping grouping)
          {
            this.grouping = grouping;
            return this;
          }

        public PINPolicy addPatternRestriction (PatternRestriction pattern)
          {
            this.patternRestrictions.add (pattern);
            return this;
          }
      }


    public class Key implements Serializable
      {
        private static final long serialVersionUID = 1L;

        LinkedHashMap<String,ExtensionInterface> extensions = new LinkedHashMap<String,ExtensionInterface> ();
        
        PostProvisioningTargetKey clone_or_update_operation;
        
        boolean key_init_done;
        
        byte[] expected_attest_mac_count;  // Two bytes
        
        private void addExtension (ExtensionInterface ei) throws IOException
          {
            if (extensions.put (ei.type, ei) != null)
              {
                bad ("Duplicate extension:" + ei.type);
              }
          }
        
        public PropertyBag[] getPropertyBags ()
          {
            Vector<PropertyBag> prop_bags = new Vector<PropertyBag> ();
            for (ExtensionInterface ei : extensions.values ())
              {
                if (ei instanceof PropertyBag)
                  {
                    prop_bags.add ((PropertyBag) ei);
                  }
              }
            return prop_bags.toArray (new PropertyBag[0]);
          }
        
        public PropertyBag addPropertyBag (String type) throws IOException
          {
            PropertyBag pb = new PropertyBag (type);
            addExtension (pb);
            return pb;
          }


        Object object;
        
        public Key setUserObject (Object object)
          {
            this.object = object;
            return this;
          }
        
        public Object getUserObject ()
          {
            return object;
          }


        public Key addExtension (String type, byte[] data) throws IOException
          {
            addExtension (new Extension (type, data));
            return this;
          }

        public Key addEncryptedExtension (String type, byte[] data) throws IOException
          {
            addExtension (new EncryptedExtension (type, encrypt (data)));
            return this;
          }

        public Key addLogotype (String type, MimeTypedObject logotype) throws IOException
          {
            addExtension (new Logotype (type, logotype));
            return this;
          }


        X509Certificate[] certificatePath;
        
        public Key setCertificatePath (X509Certificate[] certificatePath)
          {
            this.certificatePath = certificatePath;
            return this;
          }
        
        public X509Certificate[] getCertificatePath ()
          {
            return certificatePath;
          }


        byte[] encrypted_symmetric_key;
        
        public Key setSymmetricKey (byte[] symmetricKey) throws IOException
          {
            this.encrypted_symmetric_key = encrypt (symmetricKey);
            return this;
          }
        

        String[] endorsedAlgorithms;

        public Key setEndorsedAlgorithms (String[] endorsedAlgorithms) throws IOException
          {
            this.endorsedAlgorithms = BasicCapabilities.getSortedAlgorithms (endorsedAlgorithms);
            return this;
          }


        public byte[] getEncryptedSymmetricKey ()
          {
            return encrypted_symmetric_key;
          }


        byte[] encrypted_private_key;
        
        public Key setPrivateKey (byte[] privateKey) throws IOException
          {
            this.encrypted_private_key = encrypt (privateKey);
            return this;
          }

        public byte[] getEncryptedPrivateKey ()
          {
            return encrypted_private_key;
          }

        
        String friendlyName;

        public Key setFriendlyName (String friendlyName)
          {
            this.friendlyName = friendlyName;
            return this;
          }

        public String getFriendlyName ()
          {
            return friendlyName;
          }

        
        PublicKey publicKey;   // Filled in by KeyCreationRequestDecoder

        public PublicKey getPublicKey ()
          {
            return publicKey;
          }


        byte[] attestation;   // Filled in by KeyCreationRequestDecoder
        
        public byte[] getAttestation ()
          {
            return attestation;
          }


        ExportProtection exportProtection;
        
        public Key setExportProtection (ExportProtection exportProtection)
          {
            this.exportProtection = exportProtection;
            return this;
          }

        public ExportProtection getExportPolicy ()
          {
            return exportProtection;
          }
        
        
        byte[] serverSeed;
        
        public Key setServerSeed (byte[] serverSeed) throws IOException
          {
            if (serverSeed != null && serverSeed.length > SecureKeyStore.MAX_LENGTH_SERVER_SEED)
              {
                bad ("Server seed > " + SecureKeyStore.MAX_LENGTH_SERVER_SEED + " bytes");
              }
            this.serverSeed = serverSeed;
            return this;
          }
        

        boolean enablePinCaching;
        boolean enable_pin_caching_set;
        
        public Key setEnablePINCaching (boolean flag)
          {
            enablePinCaching = flag;
            enable_pin_caching_set = true;
            return this;
          }
        
        public boolean getEnablePINCachingFlag ()
          {
            return enablePinCaching;
          }


        boolean trust_anchor;
        boolean trust_anchor_set;
        
        public Key setTrustAnchor (boolean flag)
          {
            trust_anchor = flag;
            trust_anchor_set = true;
            return this;
          }
        
        public boolean getTrustAnchorFlag ()
          {
            return trust_anchor;
          }

        
        BiometricProtection biometricProtection;
        
        public Key setBiometricProtection (BiometricProtection biometricProtection) throws IOException
          {
            // TODO there must be some PIN-related tests here...
            this.biometricProtection = biometricProtection;
            return this;
          }

        public BiometricProtection getBiometricProtection ()
          {
            return biometricProtection;
          }


        DeleteProtection deleteProtection;
        
        public Key setDeleteProtection (DeleteProtection deleteProtection) throws IOException
          {
            // TODO there must be some PIN-related tests here...
            this.deleteProtection = deleteProtection;
            return this;
          }

        public DeleteProtection getDeletePolicy ()
          {
            return deleteProtection;
          }


        String id;

        public String getID ()
          {
            return id;
          }
        

        AppUsage appUsage;

        public AppUsage getAppUsage ()
          {
            return appUsage;
          }

        KeySpecifier keySpecifier;

        PINPolicy pinPolicy;
        
        public PINPolicy getPINPolicy ()
          {
            return pinPolicy;
          }

        
        byte[] presetPin;
        
        public byte[] getEncryptedPIN ()
          {
            return presetPin;
          }
        

        boolean devicePinProtection;

        public boolean getDevicePINProtection ()
          {
            return devicePinProtection;
          }
        
        
        void setPostOp (PostProvisioningTargetKey op) throws IOException
          {
            if (clone_or_update_operation != null)
              {
                bad ("Clone or Update already set for this key");
              }
            if (pinPolicy != null || devicePinProtection)
              {
                bad ("Clone/Update keys cannot be PIN protected");
              }
            clone_or_update_operation = op;
          }
        
     
        public Key setClonedKeyProtection (String oldClientSessionId, 
                                                     String oldServerSessionId,
                                                     X509Certificate oldKey,
                                                     PublicKey keyManagementKey) throws IOException
          {
            PostProvisioningTargetKey op = addPostOperation (oldClientSessionId,
                                                             oldServerSessionId,
                                                             oldKey,
                                                             PostOperation.CLONE_KEY_PROTECTION,
                                                             keyManagementKey);
            setPostOp (op);
            return this;
          }

        public Key setUpdatedKey (String oldClientSessionId, 
                                            String oldServerSessionId,
                                            X509Certificate oldKey,
                                            PublicKey keyManagementKey) throws IOException
          { 
            PostProvisioningTargetKey op = addPostOperation (oldClientSessionId,
                                                             oldServerSessionId,
                                                             oldKey,
                                                             PostOperation.UPDATE_KEY,
                                                             keyManagementKey);
            setPostOp (op);
            return this;
          }

        Key (AppUsage appUsage, KeySpecifier keySpecifier, PINPolicy pinPolicy, byte[] presetPin, boolean devicePinProtection) throws IOException
          {
            this.id = key_prefix + ++next_key_id_suffix;
            this.appUsage = appUsage;
            this.keySpecifier = keySpecifier;
            this.pinPolicy = pinPolicy;
            this.presetPin = presetPin;
            this.devicePinProtection = devicePinProtection;
            if (pinPolicy != null)
              {
                if (pinPolicy.not_first)
                  {
                    if (pinPolicy.grouping == Grouping.SHARED && ((pinPolicy.preset_test == null && presetPin != null) || (pinPolicy.preset_test != null && presetPin == null)))
                      {
                        bad ("\"shared\" PIN keys must either have no \"presetPin\" " + "value or all be preset");
                      }
                  }
                else
                  {
                    pinPolicy.not_first = true;
                    pinPolicy.preset_test = presetPin;
                  }
              }
          }

        void writeRequest (DOMWriterHelper wr) throws IOException, GeneralSecurityException
          {
            key_init_done = true;
            MacGenerator key_pair_mac = new MacGenerator ();
            key_pair_mac.addString (id);
            key_pair_mac.addString (key_attestation_algorithm);
            key_pair_mac.addArray (serverSeed == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : serverSeed);
            key_pair_mac.addString (pinPolicy == null ? 
                                      SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE 
                                                       :
                                      pinPolicy.id);
            if (getEncryptedPIN () == null)
              {
                key_pair_mac.addString (SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE);
              }
            else
              {
                key_pair_mac.addArray (getEncryptedPIN ());
              }
            key_pair_mac.addBool (devicePinProtection);
            key_pair_mac.addBool (enablePinCaching);
            key_pair_mac.addByte (biometricProtection == null ?
                       BiometricProtection.NONE.getSksValue () : biometricProtection.getSksValue ());
            key_pair_mac.addByte (exportProtection == null ?
                ExportProtection.NON_EXPORTABLE.getSksValue () : exportProtection.getSksValue ());
            key_pair_mac.addByte (deleteProtection == null ?
                       DeleteProtection.NONE.getSksValue () : deleteProtection.getSksValue ());
            key_pair_mac.addByte (appUsage.getSksValue ());
            key_pair_mac.addString (friendlyName == null ? "" : friendlyName);
            key_pair_mac.addString (keySpecifier.getKeyAlgorithm ().getURI ());
            key_pair_mac.addArray (keySpecifier.getParameters () == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : keySpecifier.getParameters ());
            if (endorsedAlgorithms != null) for (String algorithm : endorsedAlgorithms)
              {
                key_pair_mac.addString (algorithm);
              }

            wr.addChildElement (KEY_ENTRY_SPECIFIER_ELEM);

            wr.setStringAttribute (ID_ATTR, id);

            if (serverSeed != null)
              {
                wr.setBinaryAttribute (SERVER_SEED_ATTR, serverSeed);
              }

            if (devicePinProtection)
              {
                wr.setBooleanAttribute (DEVICE_PIN_PROTECTION_ATTR, true);
              }

            if (presetPin != null)
              {
                wr.setBinaryAttribute (ENCRYPTED_PRESET_PIN_ATTR, presetPin);
              }

            if (enable_pin_caching_set)
              {
                if (enablePinCaching && (pinPolicy == null || pinPolicy.inputMethod != InputMethod.TRUSTED_GUI))
                  {
                    bad ("\"" + ENABLE_PIN_CACHING_ATTR +"\" must be combined with " + InputMethod.TRUSTED_GUI.toString ());
                  }
                wr.setBooleanAttribute (ENABLE_PIN_CACHING_ATTR, enablePinCaching);
              }

            if (biometricProtection != null)
              {
                wr.setStringAttribute (BIOMETRIC_PROTECTION_ATTR, biometricProtection.getProtocolName ());
              }

            if (exportProtection != null)
              {
                wr.setStringAttribute (EXPORT_PROTECTION_ATTR, exportProtection.getProtocolName ());
              }

            if (deleteProtection != null)
              {
                wr.setStringAttribute (DELETE_PROTECTION_ATTR, deleteProtection.getProtocolName ());
              }

            if (friendlyName != null)
              {
                wr.setStringAttribute (FRIENDLY_NAME_ATTR, friendlyName);
              }

            wr.setStringAttribute (APP_USAGE_ATTR, appUsage.getProtocolName ());

            wr.setStringAttribute (KEY_ALGORITHM_ATTR, keySpecifier.getKeyAlgorithm ().getURI ());
            if (keySpecifier.getParameters () != null)
              {
                wr.setBinaryAttribute (KEY_PARAMETERS_ATTR, keySpecifier.getParameters ());
              }

            if (endorsedAlgorithms != null)
              {
                wr.setListAttribute (ENDORSED_ALGORITHMS_ATTR, endorsedAlgorithms);
              }

            wr.setBinaryAttribute (MAC_ATTR, mac (key_pair_mac.getResult (), SecureKeyStore.METHOD_CREATE_KEY_ENTRY));
            
            expected_attest_mac_count = getMacSequenceCounterAndUpdate ();
            
            wr.getParent ();
          }
      }

    public Key[] getKeys ()
      {
        return requested_keys.values ().toArray (new Key[0]);
      }

    public ProtocolPhase getProtocolPhase ()
      {
        return current_phase;
      }

    ServerCryptoInterface serverCryptoInterface;

    BasicCapabilities basic_capabilities = new BasicCapabilities (false);
    
    HashMap<String,HashSet<String>> client_attribute_values;

    ProtocolPhase current_phase = ProtocolPhase.PLATFORM_NEGOTIATION;
    
    boolean request_phase = true;
    
    int next_personal_code = 1;

    String key_prefix = "Key.";

    int next_key_id_suffix = 0;

    String pin_prefix = "PIN.";

    int next_pin_id_suffix = 0;

    String puk_prefix = "PUK.";

    int next_puk_id_suffix = 0;

    short mac_sequence_counter;

    LinkedHashMap<String,Key> requested_keys = new LinkedHashMap<String,Key> ();

    Vector<ImagePreference> image_preferences; 

    String serverSessionId;

    String clientSessionId;
    
    String issuer_uri;

    int sessionLifeTime;

    short sessionKeyLimit;
    
    String provisioning_session_algorithm = SecureKeyStore.ALGORITHM_SESSION_ATTEST_1;
    
    String key_attestation_algorithm;
    
    ECPublicKey server_ephemeral_key;
    
    ECPublicKey client_ephemeral_key;
    
    PublicKey keyManagementKey;
    
    byte[] saved_close_nonce;
    
    byte[] vm_nonce;
    
    X509Certificate device_certificate;
    
    PostProvisioningTargetKey addPostOperation (String oldClientSessionId,
                                                String oldServerSessionId,
                                                X509Certificate oldKey,
                                                PostOperation operation,
                                                PublicKey keyManagementKey) throws IOException
      {
        try
          {
            PostProvisioningTargetKey new_post_op = new PostProvisioningTargetKey (oldClientSessionId,
                                                                                   oldServerSessionId,
                                                                                   oldKey.getEncoded (),
                                                                                   keyManagementKey,
                                                                                   operation);
            for (PostProvisioningTargetKey post_op : post_operations)
              {
                if (post_op.equals (new_post_op))
                  {
                    if (post_op.postOperation == PostOperation.DELETE_KEY || new_post_op.postOperation == PostOperation.DELETE_KEY)
                      {
                        bad ("DeleteKey cannot be combined with other management operations");
                      }
                    if (post_op.postOperation == PostOperation.UPDATE_KEY || new_post_op.postOperation == PostOperation.UPDATE_KEY)
                      {
                        bad ("UpdateKey can only be performed once per key");
                      }
                  }
              }
            post_operations.add (new_post_op);
            return new_post_op;
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
    
    void checkSession (String clientSessionId, String serverSessionId) throws IOException
      {
        if (!this.clientSessionId.equals (clientSessionId) || !this.serverSessionId.equals (serverSessionId))
          {
            bad ("Session ID mismatch");
          }
      }
    
    private byte[] getMacSequenceCounterAndUpdate ()
      {
        int q = mac_sequence_counter++;
        return  new byte[]{(byte)(q >>> 8), (byte)(q &0xFF)};
      }

    byte[] mac (byte[] data, byte[] method) throws IOException
      {
        return serverCryptoInterface.mac (data, ArrayUtil.add (method, getMacSequenceCounterAndUpdate ()));
      }
    
    byte[] attest (byte[] data, byte[] macCounter) throws IOException, GeneralSecurityException
      {
        return serverCryptoInterface.mac (data, ArrayUtil.add (SecureKeyStore.KDF_DEVICE_ATTESTATION, macCounter)); 
      }
    
    byte[] encrypt (byte[] data) throws IOException
      {
        return serverCryptoInterface.encrypt (data);
      }
    
    void checkFinalResult (byte[] close_session_attestation) throws IOException, GeneralSecurityException
      {
        MacGenerator check = new MacGenerator ();
        check.addArray (saved_close_nonce);
        check.addString (SecureKeyStore.ALGORITHM_SESSION_ATTEST_1);
        if (!ArrayUtil.compare (attest (check.getResult (),
                                        getMacSequenceCounterAndUpdate ()),
                                close_session_attestation))
          {
            bad ("Final attestation failed!");
          }
      }
  
    static void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }
    
    boolean privacy_enabled;
    boolean privacy_enabled_set;
    
    public void setPrivacyEnabled (boolean flag) throws IOException
      {
        if (!request_phase || current_phase != ProtocolPhase.PLATFORM_NEGOTIATION)
          {
            throw new IOException ("Must be specified before any requests");
          }
        privacy_enabled_set = true;
        privacy_enabled = flag;
      }

    KeyAlgorithms ephemeral_key_algorithm = KeyAlgorithms.NIST_P_256;
    
    public void setEphemeralKeyAlgorithm (KeyAlgorithms ephemeral_key_algorithm)
      {
        this.ephemeral_key_algorithm = ephemeral_key_algorithm;
      }

 
    // Constructor
    public ServerState (ServerCryptoInterface serverCryptoInterface)
      {
        this.serverCryptoInterface = serverCryptoInterface;
      }

    
    void checkState (boolean request, ProtocolPhase expected) throws IOException
      {
        if (request ^ request_phase)
          {
            throw new IOException ("Wrong order of request versus response");
          }
        request_phase = !request_phase;
        if (current_phase != expected)
          {
            throw new IOException ("Incorrect object, expected: " + expected + " got: " + current_phase);
          }
      }


    public void update (PlatformNegotiationResponseDecoder platform_response) throws IOException
      {
        checkState (false, ProtocolPhase.PLATFORM_NEGOTIATION);
        current_phase = ProtocolPhase.PROVISIONING_INITIALIZATION;
        basic_capabilities.checkCapabilities (platform_response.basic_capabilities);
        basic_capabilities = platform_response.basic_capabilities;
        image_preferences = platform_response.image_preferences;
        vm_nonce = platform_response.nonce;
      }


    public void update (ProvisioningInitializationResponseDecoder prov_init_response, X509Certificate server_certificate) throws IOException
      {
        try
          {
            checkState (false, ProtocolPhase.PROVISIONING_INITIALIZATION);
            clientSessionId = prov_init_response.clientSessionId;
            device_certificate = prov_init_response.device_certificate_path == null ? null : prov_init_response.device_certificate_path[0];
            client_ephemeral_key = prov_init_response.client_ephemeral_key;
            client_attribute_values = prov_init_response.client_attribute_values;

            MacGenerator kdf = new MacGenerator ();
            kdf.addString (clientSessionId);
            kdf.addString (serverSessionId);
            kdf.addString (issuer_uri);
            kdf.addArray (getDeviceID ());

            MacGenerator attestation_arguments = new MacGenerator ();
            attestation_arguments.addString (clientSessionId);
            attestation_arguments.addString (serverSessionId);
            attestation_arguments.addString (issuer_uri);
            attestation_arguments.addArray (getDeviceID ());
            attestation_arguments.addString (provisioning_session_algorithm);
            attestation_arguments.addBool (device_certificate == null);
            attestation_arguments.addArray (server_ephemeral_key.getEncoded ());
            attestation_arguments.addArray (client_ephemeral_key.getEncoded ());
            attestation_arguments.addArray (keyManagementKey == null ? new byte[0] : keyManagementKey.getEncoded ());
            attestation_arguments.addInt ((int) (prov_init_response.clientTime.getTime () / 1000));
            attestation_arguments.addInt (sessionLifeTime);
            attestation_arguments.addShort (sessionKeyLimit);

            serverCryptoInterface.generateAndVerifySessionKey (client_ephemeral_key,
                                                                 kdf.getResult (),
                                                                 attestation_arguments.getResult (),
                                                                 device_certificate == null ? null : device_certificate,
                                                                 prov_init_response.attestation);
            if (((server_certificate == null ^ prov_init_response.server_certificate_fingerprint == null)) ||
                (server_certificate != null && !ArrayUtil.compare (prov_init_response.server_certificate_fingerprint, 
                                                                   HashAlgorithms.SHA256.digest (server_certificate.getEncoded ()))))
              {
                throw new IOException ("Attribute '" + SERVER_CERT_FP_ATTR + "' is missing or is invalid");
              }
            new XMLSymKeyVerifier (new SymKeyVerifierInterface()
              {
                @Override
                public boolean verifyData (byte[] data, byte[] digest, MACAlgorithms algorithm, String keyId) throws IOException
                  {
                    return ArrayUtil.compare (serverCryptoInterface.mac (data, SecureKeyStore.KDF_EXTERNAL_SIGNATURE), digest);
                  }
              }).validateEnvelopedSignature (prov_init_response, null, prov_init_response.signature, clientSessionId);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
        current_phase = ProtocolPhase.CREDENTIAL_DISCOVERY;
      }


    byte[] getDeviceID () throws GeneralSecurityException
      {
        return device_certificate == null ? SecureKeyStore.KDF_ANONYMOUS : device_certificate.getEncoded ();
      }

    public void update (CredentialDiscoveryResponseDecoder credential_discovery_response) throws IOException
      {
        checkState (false, ProtocolPhase.CREDENTIAL_DISCOVERY);
        checkSession (credential_discovery_response.clientSessionId, credential_discovery_response.serverSessionId);
        current_phase = ProtocolPhase.KEY_CREATION;
      }


    public void update (KeyCreationResponseDecoder key_create_response) throws IOException
      {
        checkState (false, ProtocolPhase.KEY_CREATION);
        checkSession (key_create_response.clientSessionId, key_create_response.serverSessionId);
        if (key_create_response.generatedKeys.size () != requested_keys.size ())
          {
            ServerState.bad ("Different number of requested and received keys");
          }
        try
          {
            for (KeyCreationResponseDecoder.GeneratedPublicKey gpk : key_create_response.generatedKeys.values ())
              {
                ServerState.Key kp = requested_keys.get (gpk.id);
                if (kp == null)
                  {
                    ServerState.bad ("Missing key id:" + gpk.id);
                  }
                if (kp.keySpecifier.key_algorithm != KeyAlgorithms.getKeyAlgorithm (kp.publicKey = gpk.publicKey, kp.keySpecifier.parameters != null))
                  {
                    ServerState.bad ("Wrong key type returned for key id:" + gpk.id);
                  }
                MacGenerator attestation = new MacGenerator ();
                // Write key attestation data
                attestation.addString (gpk.id);
                attestation.addArray (gpk.publicKey.getEncoded ());
                 if (!ArrayUtil.compare (attest (attestation.getResult (), kp.expected_attest_mac_count),
                                         kp.attestation = gpk.attestation))
                  {
                    ServerState.bad ("Attestation failed for key id:" + gpk.id);
                  }
              }
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
        current_phase = ProtocolPhase.PROVISIONING_FINALIZATION;
      }

    
    public void update (ProvisioningFinalizationResponseDecoder prov_final_response) throws IOException
      {
        checkState (false, ProtocolPhase.PROVISIONING_FINALIZATION);
        checkSession (prov_final_response.clientSessionId, prov_final_response.serverSessionId);
        try
          {
            checkFinalResult (prov_final_response.attestation);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
        current_phase = ProtocolPhase.DONE;
      }

    
    public String getDeviceID (boolean longVersion)
      {
        return DeviceID.getDeviceID (device_certificate, longVersion);
      }


    public X509Certificate getDeviceCertificate ()
      {
        return device_certificate;
      }


    public BasicCapabilities getBasicCapabilities ()
      {
        return basic_capabilities;
      }


    public HashMap<String,HashSet<String>> getClientAttributeValues ()
      {
        return client_attribute_values;
      }


    public ImagePreference[] getImagePreferences ()
      {
        return image_preferences.toArray (new ImagePreference[0]);
      }

    
    public ImagePreference[] getImagePreferences (String type)
      {
        Vector<ImagePreference> matching = new Vector<ImagePreference> ();
        for (ImagePreference impref : image_preferences)
          {
            if (impref.type.equals (type))
              {
                matching.add (impref);
              }
          }
        return matching.toArray (new ImagePreference[0]);
      }

    
    public void addPostDeleteKey (String oldClientSessionId,
                                  String oldServerSessionId,
                                  X509Certificate oldKey,
                                  PublicKey keyManagementKey) throws IOException
      {
        addPostOperation (oldClientSessionId, 
                          oldServerSessionId,
                          oldKey, 
                          PostOperation.DELETE_KEY,
                          keyManagementKey);
      }

  
    public void addPostUnlockKey (String oldClientSessionId,
                                  String oldServerSessionId,
                                  X509Certificate oldKey,
                                  PublicKey keyManagementKey) throws IOException
      {
        addPostOperation (oldClientSessionId, 
        oldServerSessionId,
        oldKey, 
        PostOperation.UNLOCK_KEY,
        keyManagementKey);
      }

    
    public String getClientSessionId ()
      {
        return clientSessionId;
      }

    public String getServerSessionId ()
      {
        return serverSessionId;
      }

    
    public PINPolicy createPINPolicy (PassphraseFormat format, int minLength, int maxLength, int retryLimit, PUKPolicy pukPolicy) throws IOException
      {
        PINPolicy pinPolicy = new PINPolicy ();
        pinPolicy.format = format;
        pinPolicy.minLength = minLength;
        pinPolicy.maxLength = maxLength;
        pinPolicy.retryLimit = retryLimit;
        pinPolicy.pukPolicy = pukPolicy;
        if (format == null)
          {
            bad ("PassphraseFormat must not be null");
          }
        if (minLength > maxLength)
          {
            bad ("minLength > maxLength");
          }
        return pinPolicy;
      }


    public PUKPolicy createPUKPolicy (byte[] puk, PassphraseFormat format, int retryLimit) throws IOException
      {
        return new PUKPolicy (encrypt (puk), format, retryLimit);
      }


    private Key addKeyProperties (AppUsage appUsage, KeySpecifier keySpecifier, PINPolicy pinPolicy, byte[] presetPin, boolean devicePinProtection) throws IOException
      {
        Key key = new Key (appUsage, keySpecifier, pinPolicy, presetPin, devicePinProtection);
        requested_keys.put (key.getID (), key);
        return key;
      }


    public Key createKeyWithPresetPIN (AppUsage appUsage, KeySpecifier keySpecifier, PINPolicy pinPolicy, byte[] pin) throws IOException
      {
        if (pinPolicy == null)
          {
            bad ("PresetPIN without PINPolicy is not allowed");
          }
        pinPolicy.userDefined = false;
        return addKeyProperties (appUsage, keySpecifier, pinPolicy, encrypt (pin), false);
      }


    public Key createKey (AppUsage appUsage, KeySpecifier keySpecifier, PINPolicy pinPolicy) throws IOException
      {
        return addKeyProperties (appUsage, keySpecifier, pinPolicy, null, false);
      }


    public Key createDevicePINProtectedKey (AppUsage appUsage, KeySpecifier keySpecifier) throws IOException
      {
        return addKeyProperties (appUsage, keySpecifier, null, null, true);
      }


    private LinkedHashMap<String,Object> service_specific_objects = new LinkedHashMap<String,Object> ();
    
    public void setServiceSpecificObject (String name, Object value)
      {
        service_specific_objects.put (name, value);
      }


    public Object getServiceSpecificObject (String name)
      {
        return service_specific_objects.get (name);
      }

    public ECPublicKey generateEphemeralKey () throws IOException
      {
        return serverCryptoInterface.generateEphemeralKey (ephemeral_key_algorithm);
      }
  }
