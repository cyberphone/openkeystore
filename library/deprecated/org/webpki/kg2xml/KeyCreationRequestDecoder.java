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

import java.util.Vector;
import java.util.Set;
import java.util.EnumSet;

import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class KeyCreationRequestDecoder extends KeyCreationRequest
  {
    public class PUKPolicy
      {
        byte[] mac;
        
        Object userData;

        PassphraseFormat format;

        short retryLimit;
        
        String id;
        
        byte[] encryptedValue;
 
        PUKPolicy (DOMReaderHelper rd) throws IOException
          {
            encryptedValue = rd.getAttributeHelper ().getBinary (ENCRYPTED_PUK_ATTR);
            retryLimit = (short)rd.getAttributeHelper ().getInt (RETRY_LIMIT_ATTR);
            id = rd.getAttributeHelper ().getString (ID_ATTR);
            format = PassphraseFormat.getPassphraseFormatFromString (rd.getAttributeHelper ().getString (FORMAT_ATTR));
            mac = rd.getAttributeHelper ().getBinary (MAC_ATTR);
          }


        public short getRetryLimit ()
          {
            return retryLimit;
          }


        public PassphraseFormat getFormat ()
          {
            return format;
          }

        public byte[] getEncryptedValue ()
          {
            return encryptedValue;
          }


        public void setUserData (Object userData)
          {
            this.userData = userData;
          }


        public Object getUserData ()
          {
            return userData;
          }

        
        public String getID ()
          {
            return id;
          }

        
        public byte[] getMac ()
          {
            return mac;
          }
      }


    public class PINPolicy
      {
        byte[] mac;
        
        String id;
        
        PUKPolicy pukPolicy;
        
        Object userData;

        PassphraseFormat format;

        short retryLimit;

        short minLength;

        short maxLength;

        Grouping grouping;

        InputMethod inputMethod;

        Set<PatternRestriction> patternRestrictions = EnumSet.noneOf (PatternRestriction.class);

        PINPolicy (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            
            mac = ah.getBinary (MAC_ATTR);
            
            id = ah.getString (ID_ATTR);

            minLength = (short)ah.getInt (MIN_LENGTH_ATTR);

            maxLength = (short)ah.getInt (MAX_LENGTH_ATTR);

            if (minLength > maxLength)
              {
                bad ("PIN length: min > max");
              }

            retryLimit = (short)ah.getInt (RETRY_LIMIT_ATTR);

            format = PassphraseFormat.getPassphraseFormatFromString (ah.getString (FORMAT_ATTR));

            grouping = Grouping.getGroupingFromString (ah.getStringConditional (GROUPING_ATTR, Grouping.NONE.getProtocolName ()));

            inputMethod = InputMethod.getInputMethodFromString (ah.getStringConditional (INPUT_METHOD_ATTR, InputMethod.ANY.getProtocolName ()));
            
            userModifiable = ah.getBooleanConditional (USER_MODIFIABLE_ATTR, true);

            String pr[] = ah.getListConditional (PATTERN_RESTRICTIONS_ATTR);
            if (pr != null)
              {
                for (String pattern : pr)
                  {
                    patternRestrictions.add (PatternRestriction.getPatternRestrictionFromString (pattern));
                  }
              }
          }


        public Set<PatternRestriction> getPatternRestrictions ()
          {
            return patternRestrictions;
          }


        public short getMinLength ()
          {
            return minLength;
          }


        public short getMaxLength ()
          {
            return maxLength;
          }


        public short getRetryLimit ()
          {
            return retryLimit;
          }


        public PassphraseFormat getFormat ()
          {
            return format;
          }


        public Grouping getGrouping ()
          {
            return grouping;
          }


        boolean userDefined = true;
        
        public boolean getUserDefinedFlag ()
          {
            return userDefined;
          }


        boolean userModifiable;
        
        public boolean getUserModifiableFlag ()
          {
            return userModifiable;
          }


        public InputMethod getInputMethod ()
          {
            return inputMethod;
          }


        public String getID ()
          {
            return id;
          }


        public byte[] getMac ()
          {
            return mac;
          }


        public void setUserData (Object userData)
          {
            this.userData = userData;
          }


        public Object getUserData ()
          {
            return userData;
          }

        
        public PUKPolicy getPUKPolicy ()
          {
            return pukPolicy;
          }
      }


    public class KeyObject
      {
        String id;
        
        byte[] mac;
        
        boolean start_of_puk_group;

        boolean start_of_pin_group;

        PINPolicy pinPolicy;
        
        byte[] presetPin;

        byte[] userSetPin;

        boolean devicePinProtected;
        
        AppUsage appUsage;

        KeySpecifier keySpecifier;
        
        KeyObject (DOMReaderHelper rd, 
                   PINPolicy pinPolicy,
                   boolean start_of_pin_group) throws IOException
          {
            rd.getNext (KEY_ENTRY_SPECIFIER_ELEM);
            this.pinPolicy = pinPolicy;
            this.start_of_pin_group = start_of_pin_group;
 
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

            id = ah.getString (ID_ATTR);
            
            

            mac = ah.getBinary (MAC_ATTR);

            friendlyName = ah.getStringConditional (FRIENDLY_NAME_ATTR);
            
            devicePinProtected = ah.getBooleanConditional (DEVICE_PIN_PROTECTION_ATTR, false);
            
            presetPin = ah.getBinaryConditional (ENCRYPTED_PRESET_PIN_ATTR);
            if (presetPin != null)
              {
                pinPolicy.userDefined = false;
              }

            appUsage = AppUsage.getAppUsageFromString (ah.getString (APP_USAGE_ATTR));

            enablePinCaching = ah.getBooleanConditional (ENABLE_PIN_CACHING_ATTR);
            
            endorsedAlgorithms = ah.getListConditional (ENDORSED_ALGORITHMS_ATTR);
            if (endorsedAlgorithms == null)
              {
                endorsedAlgorithms = new String[0];
              }
            else
              {
                endorsedAlgorithms = BasicCapabilities.getSortedAlgorithms (endorsedAlgorithms);
              }

            serverSeed = ah.getBinaryConditional (SERVER_SEED_ATTR);

            biometricProtection = BiometricProtection.getBiometricProtectionFromString (ah.getStringConditional (BIOMETRIC_PROTECTION_ATTR, 
                                                                                         BiometricProtection.NONE.getProtocolName ()));

            deleteProtection = DeleteProtection.getDeletePolicyFromString (ah.getStringConditional (DELETE_PROTECTION_ATTR, 
                                                                            DeleteProtection.NONE.getProtocolName ()));
            exportProtection = ExportProtection.getExportPolicyFromString (ah.getStringConditional (EXPORT_PROTECTION_ATTR, 
                                                                            ExportProtection.NON_EXPORTABLE.getProtocolName ()));

            keySpecifier = new KeySpecifier (ah.getString (KEY_ALGORITHM_ATTR),
                                              ah.getBinaryConditional (KEY_PARAMETERS_ATTR));
          }


        public PINPolicy getPINPolicy ()
          {
            return pinPolicy;
          }


        public byte[] getPresetPIN ()
          {
            return presetPin;
          }


        public boolean isStartOfPINPolicy ()
          {
            return start_of_pin_group;
          }


        public boolean isStartOfPUKPolicy ()
          {
            return start_of_puk_group;
          }


        public boolean isDevicePINProtected ()
          {
            return devicePinProtected;
          }


        public KeySpecifier getKeySpecifier ()
          {
            return keySpecifier;
          }


        public AppUsage getAppUsage ()
          {
            return appUsage;
          }


        public String getID ()
          {
            return id;
          }

        
        public byte[] getMac ()
          {
            return mac;
          }
        

        byte[] serverSeed;
        
        public byte[] getServerSeed ()
          {
            return serverSeed;
          }
        
        BiometricProtection biometricProtection;

        public BiometricProtection getBiometricProtection ()
          {
            return biometricProtection;
          }

        
        ExportProtection exportProtection;
        
        public ExportProtection getExportProtection ()
          {
            return exportProtection;
          }

        
        DeleteProtection deleteProtection;
        
        public DeleteProtection getDeleteProtection ()
          {
            return deleteProtection;
          }

        
        boolean enablePinCaching;
        
        public boolean getEnablePINCachingFlag ()
          {
            return enablePinCaching;
          }

      
        String friendlyName;
        
        public String getFriendlyName ()
          {
            return friendlyName;
          }
        
        
        String[] endorsedAlgorithms;

        public String[] getEndorsedAlgorithms ()
          {
            return endorsedAlgorithms;
          }

        
        public byte[] getSKSPINValue ()
          {
            return userSetPin == null ? getPresetPIN () : userSetPin;
          }
      }

    public class UserPINError
      {
        public boolean length_error;
        public boolean syntax_error;
        public boolean unique_error;
        public AppUsage unique_error_app_usage;
        public PatternRestriction pattern_error;
      }
    

    public class UserPINDescriptor
      {
        PINPolicy pinPolicy;
        AppUsage appUsage;
        
        private UserPINDescriptor (PINPolicy pinPolicy, AppUsage appUsage)
          {
            this.pinPolicy = pinPolicy;
            this.appUsage = appUsage;
          }

        public PINPolicy getPINPolicy ()
          {
            return pinPolicy;
          }

        public AppUsage getAppUsage ()
          {
            return appUsage;
          }
        
        public UserPINError setPIN (String pin_string_value, boolean set_value_on_success)
          {
            UserPINError error = new UserPINError ();

            byte[] pin = null;
            try
              {
                if (pin_string_value.length () > 0 && pinPolicy.format == PassphraseFormat.BINARY)
                  {
                    pin = DebugFormatter.getByteArrayFromHex (pin_string_value);
                  }
                else
                  {
                    pin = pin_string_value.getBytes ("UTF-8");
                  }
              }
            catch (IOException e)
              {
                error.syntax_error = true;
                return error;
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN length
            ///////////////////////////////////////////////////////////////////////////////////
            if (pinPolicy.minLength > pin.length || pinPolicy.maxLength < pin.length)
              {
                error.length_error = true;
                return error;
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN syntax
            ///////////////////////////////////////////////////////////////////////////////////
            boolean upperalpha = false;
            boolean loweralpha = false;
            boolean number = false;
            boolean nonalphanum = false;
            for (int i = 0; i < pin.length; i++)
              {
                int c = pin[i];
                if (c >= 'A' && c <= 'Z')
                  {
                    upperalpha = true;
                  }
                else if (c >= 'a' && c <= 'z')
                  {
                    loweralpha = true;
                  }
                else if (c >= '0' && c <= '9')
                  {
                    number = true;
                  }
                else
                  {
                    nonalphanum = true;
                  }
              }
            if ((pinPolicy.format == PassphraseFormat.NUMERIC && (loweralpha || nonalphanum || upperalpha)) ||
                (pinPolicy.format == PassphraseFormat.ALPHANUMERIC && (loweralpha || nonalphanum)))
              {
                error.syntax_error = true;
                return error;
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check PIN patterns
            ///////////////////////////////////////////////////////////////////////////////////
            if (pinPolicy.patternRestrictions.contains (PatternRestriction.MISSING_GROUP))
              {
                if (!upperalpha || !number ||
                    (pinPolicy.format == PassphraseFormat.STRING && (!loweralpha || !nonalphanum)))
                  {
                    error.pattern_error = PatternRestriction.MISSING_GROUP;
                    return error;
                  }
              }
            if (pinPolicy.patternRestrictions.contains (PatternRestriction.SEQUENCE))
              {
                byte c = pin[0];
                byte f = (byte)(pin[1] - c);
                boolean seq = (f == 1) || (f == -1);
                for (int i = 1; i < pin.length; i++)
                  {
                    if ((byte)(c + f) != pin[i])
                      {
                        seq = false;
                        break;
                      }
                    c = pin[i];
                  }
                if (seq)
                  {
                    error.pattern_error = PatternRestriction.SEQUENCE;
                    return error;
                  }
              }
            if (pinPolicy.patternRestrictions.contains (PatternRestriction.REPEATED))
              {
                for (int i = 0; i < pin.length; i++)
                  {
                    byte b = pin[i];
                    for (int j = 0; j < pin.length; j++)
                      {
                        if (j != i && b == pin[j])
                          {
                            error.pattern_error = PatternRestriction.REPEATED;
                            return error;
                          }
                      }
                  }
              }
            if (pinPolicy.patternRestrictions.contains (PatternRestriction.TWO_IN_A_ROW) ||
                pinPolicy.patternRestrictions.contains (PatternRestriction.THREE_IN_A_ROW))
              {
                int max = pinPolicy.patternRestrictions.contains (PatternRestriction.THREE_IN_A_ROW) ? 3 : 2;
                byte c = pin [0];
                int same_count = 1;
                for (int i = 1; i < pin.length; i++)
                  {
                    if (c == pin[i])
                      {
                        if (++same_count == max)
                          {
                            error.pattern_error = max == 2 ? PatternRestriction.TWO_IN_A_ROW : PatternRestriction.THREE_IN_A_ROW;
                            return error;
                          }
                      }
                    else
                      {
                        same_count = 1;
                        c = pin[i];
                      }
                  }
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // Check that PIN grouping rules are followed
            ///////////////////////////////////////////////////////////////////////////////////
            Vector<KeyObject> keys_needing_pin = new Vector<KeyObject> ();
            for (KeyObject key : request_objects)
              {
                if (key.pinPolicy == pinPolicy)
                  {
                    switch (pinPolicy.grouping)
                      {
                        case NONE:
                          if (key.userSetPin == null)
                            {
                              keys_needing_pin.add (key);
                              break;
                            }
                          continue;
 
                        case SHARED:
                          keys_needing_pin.add (key);
                          continue;
                  
                        case UNIQUE:
                          if (appUsage == key.appUsage)
                            {
                              keys_needing_pin.add (key);
                            }
                          else
                            {
                              if (key.userSetPin != null && ArrayUtil.compare (pin, key.userSetPin))
                                {
                                  error.unique_error = true;
                                  error.unique_error_app_usage = key.appUsage;
                                  return error;
                                }
                            }
                          continue;

                        case SIGNATURE_PLUS_STANDARD:
                          if ((appUsage == AppUsage.SIGNATURE) ^ (key.appUsage == AppUsage.SIGNATURE))
                            {
                              if (key.userSetPin != null && ArrayUtil.compare (pin, key.userSetPin))
                                {
                                  error.unique_error = true;
                                  error.unique_error_app_usage = key.appUsage;
                                  return error;
                                }
                            }
                          else
                            {
                              keys_needing_pin.add (key);
                            }
                          continue;
                      }
                    break;
                  }
              }

            ///////////////////////////////////////////////////////////////////////////////////
            // We did it!  Assign the PIN to the associated keys or just return null=success
            ///////////////////////////////////////////////////////////////////////////////////
            if (set_value_on_success)
              {
                for (KeyObject key : keys_needing_pin)
                  {
                    key.userSetPin = pin;
                  }
              }
            return null;
          }
      }


    public Vector<KeyObject> getKeyObjects () throws IOException
      {
        return request_objects;
      }


    public Vector<UserPINDescriptor> getUserPINDescriptors ()
      {
        Vector<UserPINDescriptor> user_pin_policies = new Vector<UserPINDescriptor>();
        for (KeyObject key: request_objects)
          {
            if (key.getPINPolicy () != null && key.getPINPolicy ().getUserDefinedFlag ())
              {
                UserPINDescriptor pin_desc = new UserPINDescriptor (key.pinPolicy, key.appUsage);
                if (key.pinPolicy.grouping == Grouping.NONE)
                  {
                    user_pin_policies.add (pin_desc);
                  }
                else 
                  {
                    for (UserPINDescriptor upd2 : user_pin_policies)
                      {
                        if (upd2.pinPolicy == key.pinPolicy)
                          {
                            if (key.pinPolicy.grouping == Grouping.SHARED)
                              {
                                pin_desc = null;
                                break;
                              }
                            if (key.pinPolicy.grouping == Grouping.UNIQUE)
                              {
                                if (upd2.appUsage == key.appUsage)
                                  {
                                    pin_desc = null;
                                    break;
                                  }
                              }
                            else
                              {
                                if ((upd2.appUsage == AppUsage.SIGNATURE) ^ (key.appUsage != AppUsage.SIGNATURE))
                                  {
                                    pin_desc = null;
                                    break;
                                  }
                              }
                          }
                      }
                    if (pin_desc != null)
                      {
                        user_pin_policies.add (pin_desc);
                      }
                  }
              }
          }
        return user_pin_policies;
      }

    
    private void bad (String error_msg) throws IOException
      {
        throw new IOException (error_msg);
      }


    private KeyObject readKeyProperties (DOMReaderHelper rd,
                                         PINPolicy pinPolicy,
                                         boolean start_of_pin_group) throws IOException
      {
        KeyObject rk = new KeyObject (rd, pinPolicy, start_of_pin_group);
        request_objects.add (rk);
        return rk;
      }
      

    private void readKeyProperties (DOMReaderHelper rd) throws IOException
      {
        request_objects.add (new KeyObject (rd, null, false));
      }


    private void readPINPolicy (DOMReaderHelper rd, boolean puk_start, PUKPolicy pukPolicy) throws IOException
      {
        boolean start = true;
        rd.getNext (PIN_POLICY_SPECIFIER_ELEM);
        PINPolicy upp = new PINPolicy (rd);
        upp.pukPolicy = pukPolicy;
        rd.getChild ();
        do
          {
            KeyObject rk = readKeyProperties (rd, upp, start);
            rk.start_of_puk_group = puk_start;
            puk_start = false;
            start = false;
          }
        while (rd.hasNext ());
        rd.getParent ();
      }


    private Vector<KeyObject> request_objects = new Vector<KeyObject> ();
      
    private String submitUrl;

    private boolean deferred_certification;

    private XMLSignatureWrapper signature;  // Optional

    private String serverSessionId;

    private String clientSessionId;

    public String getClientSessionId ()
      {
        return clientSessionId;
      }


    public String getServerSessionId ()
      {
        return serverSessionId;
      }


    public String getSubmitUrl ()
      {
        return submitUrl;
      }


    
    String key_entry_algorithm;
    
    public String getKeyEntryAlgorithm ()
      {
        return key_entry_algorithm;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, serverSessionId);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    public boolean getDeferredCertificationFlag ()
      {
        return deferred_certification;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        serverSessionId = ah.getString (ID_ATTR);

        clientSessionId = ah.getString (CLIENT_SESSION_ID_ATTR);

        submitUrl = ah.getString (SUBMIT_URL_ATTR);

        deferred_certification = ah.getBooleanConditional (DEFERRED_CERTIFICATION_ATTR);

        key_entry_algorithm = ah.getString (KEY_ENTRY_ALGORITHM_ATTR);

        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the request and management elements [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
         while (true)
          {
            if (rd.hasNext (KEY_ENTRY_SPECIFIER_ELEM))
              {
                readKeyProperties (rd);
              }
            else if (rd.hasNext (PUK_POLICY_SPECIFIER_ELEM))
              {
                boolean start = true;
                rd.getNext (PUK_POLICY_SPECIFIER_ELEM);
                PUKPolicy pk = new PUKPolicy (rd);
                rd.getChild ();
                do
                  {
                    readPINPolicy (rd, start, pk);
                    start = false;
                  }
                while (rd.hasNext ());
                rd.getParent ();
              }
            else if (rd.hasNext (PIN_POLICY_SPECIFIER_ELEM))
              {
                readPINPolicy (rd, false, null);
              }
            else break;
          }
 
        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ()) // Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }

  }

