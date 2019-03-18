/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.sks.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;

import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.ECDomains;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.keygen2.KeySpecifier;
import org.webpki.keygen2.KeyGen2URIs;
import org.webpki.keygen2.ServerCryptoInterface;

import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.KeyData;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

public class ProvSess
  {
    static class SoftHSM implements ServerCryptoInterface
      {
        ////////////////////////////////////////////////////////////////////////////////////////
        // Private and secret keys would in a HSM implementation be represented as handles
        ////////////////////////////////////////////////////////////////////////////////////////
        private static LinkedHashMap<PublicKey,PrivateKey> key_management_keys = new LinkedHashMap<PublicKey,PrivateKey> ();
        
        static private void addKMK (KeyStore km_keystore) throws IOException, GeneralSecurityException
          {
            key_management_keys.put (km_keystore.getCertificate ("mykey").getPublicKey (),
                                     (PrivateKey) km_keystore.getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
          }
        
        static
          {
            try
              {
                addKMK (DemoKeyStore.getMybankDotComKeyStore ());
                addKMK (DemoKeyStore.getSubCAKeyStore ());
                addKMK (DemoKeyStore.getECDSAStore ());
              }
            catch (Exception e)
              {
                throw new RuntimeException (e);
              }
          }
        
        ECPrivateKey server_ec_private_key;
        
        byte[] session_key;
        
        @Override
        public ECPublicKey generateEphemeralKey () throws IOException, GeneralSecurityException
          {
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec (ECDomains.P_256.getJCEName ());
            generator.initialize (eccgen, new SecureRandom ());
            KeyPair kp = generator.generateKeyPair();
            server_ec_private_key = (ECPrivateKey) kp.getPrivate ();
            return (ECPublicKey) kp.getPublic ();
          }
  
        @Override
        public void generateAndVerifySessionKey (ECPublicKey client_ephemeral_key,
                                                 byte[] kdf_data,
                                                 byte[] session_key_mac_data,
                                                 X509Certificate device_certificate,
                                                 byte[] session_attestation) throws IOException, GeneralSecurityException
          {
  
            // SP800-56A C(2, 0, ECC CDH)
            KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
            key_agreement.init (server_ec_private_key);
            key_agreement.doPhase (client_ephemeral_key, true);
            byte[] Z = key_agreement.generateSecret ();
  
            // The custom KDF
            Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (Z, "RAW"));
            session_key = mac.doFinal (kdf_data);
            
            // The session key signature
            mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (session_key, "RAW"));
            byte[] session_key_attest = mac.doFinal (session_key_mac_data);
            
            if (device_certificate == null)
              {
                if (!ArrayUtil.compare (session_key_attest, session_attestation))
                  {
                    throw new IOException ("Verify attestation failed");
                  }
              }
            else
              {
                PublicKey device_public_key = device_certificate.getPublicKey ();
                SignatureAlgorithms signature_algorithm = device_public_key instanceof RSAPublicKey ?
                    SignatureAlgorithms.RSA_SHA256 : SignatureAlgorithms.ECDSA_SHA256;
    
                // Verify that the session key signature was signed by the device key
                Signature verifier = Signature.getInstance (signature_algorithm.getJCEName ());
                verifier.initVerify (device_public_key);
                verifier.update (session_key_attest);
                if (!verifier.verify (session_attestation))
                  {
                    throw new IOException ("Verify provisioning signature failed");
                  }
              }
          }
  
        @Override
        public byte[] mac (byte[] data, byte[] key_modifier) throws IOException, GeneralSecurityException
          {
            Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (ArrayUtil.add (session_key, key_modifier), "RAW"));
            return mac.doFinal (data);
          }
  
        @Override
        public byte[] decrypt (byte[] data) throws IOException, GeneralSecurityException
          {
            byte[] key = mac (SecureKeyStore.KDF_ENCRYPTION_KEY, new byte[0]);
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            crypt.init (Cipher.DECRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (data, 0, 16));
            return crypt.doFinal (data, 16, data.length - 16);
          }
  
        @Override
        public byte[] encrypt (byte[] data) throws IOException, GeneralSecurityException
          {
            byte[] key = mac (SecureKeyStore.KDF_ENCRYPTION_KEY, new byte[0]);
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom ().nextBytes (iv);
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
            return ArrayUtil.add (iv, crypt.doFinal (data));
          }

        @Override
        public byte[] generateNonce () throws IOException, GeneralSecurityException
          {
            byte[] rnd = new byte[32];
            new SecureRandom ().nextBytes (rnd);
            return rnd;
          }

        @Override
        public byte[] generateKeyManagementAuthorization (PublicKey key_management_key, byte[] data) throws IOException, GeneralSecurityException
          {
            Signature km_sign = Signature.getInstance (key_management_key instanceof RSAPublicKey ? "SHA256WithRSA" : "SHA256WithECDSA");
            km_sign.initSign (key_management_keys.get (key_management_key));
            km_sign.update (data);
            return km_sign.sign ();
          }

        @Override
        public PublicKey[] enumerateKeyManagementKeys () throws IOException, GeneralSecurityException
          {
            return key_management_keys.keySet ().toArray (new PublicKey[0]);
          }
      }
    
    
    SoftHSM server_sess_key = new SoftHSM ();

    String session_key_algorithm = KeyGen2URIs.ALGORITHMS.SESSION_KEY_1;
    
    static final String ISSUER_URI = "http://issuer.example.com/provsess";
    
    Date client_time;
    
    int provisioning_handle;
    
    int session_life_time = 10000;
    
    String server_session_id;
    
    String client_session_id;
    
    ECPublicKey server_ephemeral_key;
    
    Integer kmk_id;
    
    short mac_sequence_counter;
    
    SecureKeyStore sks;
    
    Device device;
    
    boolean privacy_enabled;
    
    boolean override_export_protection;
    
    byte overriden_export_protection;
    
    boolean user_defined_pins = true;
    
    boolean user_modifiable_pins = false;
    
    boolean device_pin_protected = false;
    
    InputMethod input_method = InputMethod.ANY;
    
    static class MacGenerator
      {
        private ByteArrayOutputStream baos;
        
        MacGenerator ()
          {
            baos = new ByteArrayOutputStream ();
          }
        
        private byte[] short2bytes (int s)
          {
            return new byte[]{(byte)(s >>> 8), (byte)s};
          }
  
        private byte[] int2bytes (int i)
          {
            return new byte[]{(byte)(i >>> 24), (byte)(i >>> 16), (byte)(i >>> 8), (byte)i};
          }
  
        void addBlob (byte[] data) throws IOException
          {
            baos.write (int2bytes (data.length));
            baos.write (data);
          }
  
        void addArray (byte[] data) throws IOException
          {
            baos.write(short2bytes (data.length));
            baos.write (data);
          }
        
        void addString (String string) throws IOException
          {
            addArray (string.getBytes ("UTF-8"));
          }
        
        void addInt (int i) throws IOException
          {
            baos.write (int2bytes (i));
          }
        
        void addShort (int s) throws IOException
          {
            baos.write (short2bytes (s));
          }
        
        void addByte (byte b)
          {
            baos.write (b);
          }
        
        void addBool (boolean flag)
          {
            baos.write (flag ? (byte) 0x01 : (byte) 0x00);
          }
        
        byte[] getResult ()
          {
            return baos.toByteArray ();
          }
       
      }


    private byte[] getMACSequenceCounterAndUpdate ()
      {
        int q = mac_sequence_counter++;
        return  new byte[]{(byte)(q >>> 8), (byte)(q &0xFF)};
      }

    byte[] mac4call (byte[] data, byte[] method) throws IOException, GeneralSecurityException
      {
        return server_sess_key.mac (data, ArrayUtil.add (method, getMACSequenceCounterAndUpdate ()));
      }

    byte[] mac (byte[] data, byte[] key_modifier) throws IOException, GeneralSecurityException
      {
        return server_sess_key.mac (data, key_modifier);
      }
    
    byte[] attest (byte[] data) throws IOException, GeneralSecurityException
      {
        return server_sess_key.mac (data, ArrayUtil.add (SecureKeyStore.KDF_DEVICE_ATTESTATION, getMACSequenceCounterAndUpdate ())); 
      }
    
    void bad (String message) throws IOException
      {
        throw new IOException (message);
      }
  
    ///////////////////////////////////////////////////////////////////////////////////
    // Create provisioning session
    ///////////////////////////////////////////////////////////////////////////////////
    public ProvSess (Device device, short session_key_limit, Integer kmk_id, boolean privacy_enabled) throws GeneralSecurityException, IOException
      {
        this.device = device;
        this.kmk_id = kmk_id;
        this.privacy_enabled = privacy_enabled;
        PublicKey key_management_key = kmk_id == null ? null : server_sess_key.enumerateKeyManagementKeys ()[kmk_id];
        sks = device.sks;
        server_session_id = "S-" + Long.toHexString (new Date().getTime()) + Long.toHexString(new SecureRandom().nextLong());
        client_time = new Date ();
           ProvisioningSession sess = 
                device.sks.createProvisioningSession (session_key_algorithm,
                                                      privacy_enabled,
                                                      server_session_id,
                                                      server_ephemeral_key = server_sess_key.generateEphemeralKey (),
                                                      ISSUER_URI,
                                                      key_management_key,
                                                      (int)(client_time.getTime () / 1000),
                                                      session_life_time,
                                                      session_key_limit);
           client_session_id = sess.getClientSessionID ();
           provisioning_handle = sess.getProvisioningHandle ();
           
           MacGenerator kdf = new MacGenerator ();
           kdf.addString (client_session_id);
           kdf.addString (server_session_id);
           kdf.addString (ISSUER_URI);
           kdf.addArray (getDeviceID ());

           MacGenerator session_key_mac_data = new MacGenerator ();
           session_key_mac_data.addString (session_key_algorithm);
           session_key_mac_data.addBool (privacy_enabled);
           session_key_mac_data.addArray (server_ephemeral_key.getEncoded ());
           session_key_mac_data.addArray (sess.getClientEphemeralKey ().getEncoded ());
           session_key_mac_data.addArray (key_management_key == null ? new byte[0] : key_management_key.getEncoded ());
           session_key_mac_data.addInt ((int) (client_time.getTime () / 1000));
           session_key_mac_data.addInt (session_life_time);
           session_key_mac_data.addShort (session_key_limit);

           server_sess_key.generateAndVerifySessionKey (sess.getClientEphemeralKey (),
                                                        kdf.getResult (),
                                                        session_key_mac_data.getResult (),
                                                        privacy_enabled ? null : device.device_info.getCertificatePath ()[0],
                                                        sess.getAttestation ());
     }
    
    public ProvSess (Device device, short session_key_limit, Integer kmk_id) throws GeneralSecurityException, IOException
      {
        this (device, session_key_limit, kmk_id, false);
      }
    
    public ProvSess (Device device) throws GeneralSecurityException, IOException
      {
        this (device, (short) 50, null);
      }

    public ProvSess (Device device, short session_key_limit) throws GeneralSecurityException, IOException
      {
        this (device, session_key_limit, null);
      }

    public ProvSess (Device device, Integer kmk_id) throws GeneralSecurityException, IOException
      {
        this (device, (short) 50, kmk_id);
      }

    public void closeSession () throws IOException, GeneralSecurityException
      {
        byte[] nonce = server_sess_key.generateNonce ();
        MacGenerator close = new MacGenerator ();
        close.addString (client_session_id);
        close.addString (server_session_id);
        close.addString (ISSUER_URI);
        close.addArray (nonce);
        byte[] result = sks.closeProvisioningSession (provisioning_handle,
                                                      nonce,
                                                      mac4call (close.getResult (),
                                                      SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION));
        MacGenerator check = new MacGenerator ();
        check.addArray (nonce);
        check.addString (KeyGen2URIs.ALGORITHMS.SESSION_KEY_1);
        if (!ArrayUtil.compare (attest (check.getResult ()), result))
          {
            bad ("Final attestation failed!");
          }
      }
    
    public void abortSession () throws IOException
      {
        sks.abortProvisioningSession (provisioning_handle);
      }
    
    
    public void overrideExportProtection (byte export_policy)
      {
        override_export_protection = true;
        overriden_export_protection = export_policy;
      }
    
    public void makePINsServerDefined ()
      {
        user_defined_pins = false;
      }

    public void makePINsUserModifiable ()
      {
        user_modifiable_pins = true;
      }
    
    public void setInputMethod (InputMethod input_method)
      {
        this.input_method = input_method;
      }

    public byte[] getPassphraseBytes (PassphraseFormat format, String passphrase) throws IOException
      {
        if (format == PassphraseFormat.BINARY)
          {
            return DebugFormatter.getByteArrayFromHex (passphrase);
          }
        return passphrase.getBytes ("UTF-8");
      }
    
    public PUKPol createPUKPolicy (String id, PassphraseFormat format, int retry_limit, String puk_value) throws IOException, GeneralSecurityException
      {
        PUKPol puk_policy = new PUKPol ();
        byte[] encrypted_value = server_sess_key.encrypt (getPassphraseBytes (format, puk_value));
        MacGenerator puk_policy_mac = new MacGenerator ();
        puk_policy_mac.addString (id);
        puk_policy_mac.addArray (encrypted_value);
        puk_policy_mac.addByte (format.getSKSValue ());
        puk_policy_mac.addShort (retry_limit);
        puk_policy.id = id;
        puk_policy.puk_policy_handle = sks.createPUKPolicy (provisioning_handle, 
                                                            id,
                                                            encrypted_value, 
                                                            format.getSKSValue (), 
                                                            (short)retry_limit, 
                                                            mac4call (puk_policy_mac.getResult (), SecureKeyStore.METHOD_CREATE_PUK_POLICY));
        return puk_policy;
      }
    
    public PINPol createPINPolicy (String id, PassphraseFormat format, int min_length, int max_length, int retry_limit, PUKPol puk_policy) throws IOException, GeneralSecurityException
      {
        return createPINPolicy (id, format,  EnumSet.noneOf (PatternRestriction.class), Grouping.NONE, min_length, max_length, retry_limit, puk_policy);
      }
    
    public PINPol createPINPolicy (String id, 
                                   PassphraseFormat format,
                                   Set<PatternRestriction> pattern_restrictions,
                                   Grouping grouping,
                                   int min_length,
                                   int max_length, 
                                   int retry_limit,
                                   PUKPol puk_policy) throws IOException, GeneralSecurityException
      {
        PINPol pin_policy = new PINPol ();
        boolean user_defined = user_defined_pins;
        boolean user_modifiable = user_modifiable_pins;
        int puk_policy_handle = puk_policy == null ? 0 : puk_policy.puk_policy_handle;
        MacGenerator pin_policy_mac = new MacGenerator ();
        pin_policy_mac.addString (id);
        pin_policy_mac.addString (puk_policy == null ? SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE : puk_policy.id);
        pin_policy_mac.addBool (user_defined);
        pin_policy_mac.addBool (user_modifiable);
        pin_policy_mac.addByte (format.getSKSValue ());
        pin_policy_mac.addShort (retry_limit);
        pin_policy_mac.addByte (grouping.getSKSValue ());
        pin_policy_mac.addByte (PatternRestriction.getSKSValue (pattern_restrictions));
        pin_policy_mac.addShort (min_length);
        pin_policy_mac.addShort (max_length);
        pin_policy_mac.addByte (input_method.getSKSValue ());
        pin_policy.id = id;
        pin_policy.user_defined = user_defined;
        pin_policy.format = format;
        pin_policy.pin_policy_handle = sks.createPINPolicy (provisioning_handle,
                                                            id, 
                                                            puk_policy_handle,
                                                            user_defined,
                                                            user_modifiable,
                                                            format.getSKSValue (),
                                                            (short)retry_limit,
                                                            grouping.getSKSValue (),
                                                            PatternRestriction.getSKSValue (pattern_restrictions), 
                                                            (byte)min_length, 
                                                            (byte)max_length, 
                                                            input_method.getSKSValue (), 
                                                            mac4call (pin_policy_mac.getResult (), SecureKeyStore.METHOD_CREATE_PIN_POLICY));
        return pin_policy;
      }
   
    public GenKey createRSAKey (String id,
                                int rsa_size,
                                String pin_value,
                                PINPol pin_policy,
                                AppUsage key_usage) throws SKSException, IOException, GeneralSecurityException
      {
        return createRSAKey (id, rsa_size, pin_value, pin_policy, key_usage, null);
      }

    public GenKey createRSAKey (String id,
                                int rsa_size,
                                String pin_value,
                                PINPol pin_policy,
                                AppUsage key_usage,
                                String[] endorsed_algorithm) throws SKSException, IOException, GeneralSecurityException
      {
        byte[] server_seed = new byte[32];
        new SecureRandom ().nextBytes (server_seed);
        return createKey (id,
                          KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1,
                          server_seed,
                          pin_policy,
                          pin_value,
                          BiometricProtection.NONE /* biometric_protection */,
                          ExportProtection.NON_EXPORTABLE /* export_policy */,
                          DeleteProtection.NONE /* delete_policy */,
                          false /* enable_pin_caching */,
                          key_usage,
                          "" /* friendly_name */,
                          new KeySpecifier.RSA (2048, 0),
                          endorsed_algorithm);
      }
    
    public GenKey createECKey (String id,
                               String pin_value,
                               PINPol pin_policy,
                               AppUsage key_usage) throws SKSException, IOException, GeneralSecurityException
      {
        return createECKey (id, pin_value, pin_policy, key_usage, null);
      }

    public GenKey createECKey (String id,
                               String pin_value,
                               PINPol pin_policy,
                               AppUsage key_usage,
                               String[] endorsed_algorithms) throws SKSException, IOException, GeneralSecurityException
      {
        return createKey (id,
                          KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1,
                          null /* server_seed */,
                          pin_policy,
                          pin_value,
                          BiometricProtection.NONE /* biometric_protection */,
                          ExportProtection.NON_EXPORTABLE /* export_policy */,
                          DeleteProtection.NONE /* delete_policy */,
                          false /* enable_pin_caching */,
                          key_usage,
                          "" /* friendly_name */,
                          new KeySpecifier.EC (ECDomains.P_256),
                          endorsed_algorithms);
      }

    public GenKey createKey (String id,
                             String attestation_algorithm,
                             byte[] server_seed,
                             PINPol pin_policy,
                             String pin_value,
                             BiometricProtection biometric_protection,
                             ExportProtection export_protection,
                             DeleteProtection delete_protection,
                             boolean enable_pin_caching,
                             AppUsage key_usage,
                             String friendly_name,
                             KeySpecifier key_algorithm,
                             String[] endorsed_algorithms) throws SKSException, IOException, GeneralSecurityException
      {
        String[] sorted_algorithms = endorsed_algorithms == null ? new String[0] : endorsed_algorithms;
        byte actual_export_policy = override_export_protection ? overriden_export_protection : export_protection.getSKSValue ();
        MacGenerator key_pair_mac = new MacGenerator ();
        key_pair_mac.addString (id);
        key_pair_mac.addString (attestation_algorithm);
        key_pair_mac.addArray (server_seed == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : server_seed);
        byte[] encrypted_pin_value = null;
        if (pin_policy != null)
          {
            encrypted_pin_value = getPassphraseBytes (pin_policy.format, pin_value);
            if (!pin_policy.user_defined)
              {
                encrypted_pin_value = server_sess_key.encrypt (encrypted_pin_value);
              }
          }
        key_pair_mac.addString (pin_policy == null ? 
                                      SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE 
                                                   :
                                      pin_policy.id);
        if (pin_policy == null || pin_policy.user_defined)
          {
            key_pair_mac.addString (SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE);
          }
        else
          {
            key_pair_mac.addArray (encrypted_pin_value);
          }
        key_pair_mac.addBool (enable_pin_caching);
        key_pair_mac.addByte (biometric_protection.getSKSValue ());
        key_pair_mac.addByte (actual_export_policy);
        key_pair_mac.addByte (delete_protection.getSKSValue ());
        key_pair_mac.addByte (key_usage.getSKSValue ());
        key_pair_mac.addString (friendly_name == null ? "" : friendly_name);
        key_pair_mac.addArray (key_algorithm.getSKSValue ());
        for (String algorithm : sorted_algorithms)
          {
            key_pair_mac.addString (algorithm);
          }
        KeyData key_pair = sks.createKeyEntry (provisioning_handle, 
                                               id,
                                               attestation_algorithm, 
                                               server_seed,
                                               device_pin_protected,
                                               pin_policy == null ? 0 : pin_policy.pin_policy_handle, 
                                               encrypted_pin_value, 
                                               enable_pin_caching, 
                                               biometric_protection.getSKSValue (), 
                                               actual_export_policy, 
                                               delete_protection.getSKSValue (), 
                                               key_usage.getSKSValue (), 
                                               friendly_name, 
                                               key_algorithm.getSKSValue (),
                                               sorted_algorithms,
                                               mac4call (key_pair_mac.getResult (), SecureKeyStore.METHOD_CREATE_KEY_ENTRY));
        MacGenerator key_attestation = new MacGenerator ();
        key_attestation.addString (id);
        key_attestation.addArray (key_pair.getPublicKey ().getEncoded ());
        if (!ArrayUtil.compare (attest (key_attestation.getResult ()), key_pair.getAttestation ()))
          {
            bad ("Failed key attest");
          }
        GenKey key = new GenKey ();
        key.id = id;
        key.key_handle = key_pair.getKeyHandle ();
        key.public_key = key_pair.getPublicKey ();
        key.prov_sess = this;
        return key;
      }

    void setCertificate (int key_handle, String id, PublicKey public_key, X509Certificate[] certificate_path) throws IOException, GeneralSecurityException
      {
        MacGenerator set_certificate = new MacGenerator ();
        set_certificate.addArray (public_key.getEncoded ());
        set_certificate.addString (id);
        certificate_path = CertificateUtil.getSortedPath (certificate_path);
        for (X509Certificate certificate : certificate_path)
          {
            set_certificate.addArray (certificate.getEncoded ());
          }
        sks.setCertificatePath (key_handle,
                                certificate_path,
                                mac4call (set_certificate.getResult (), SecureKeyStore.METHOD_SET_CERTIFICATE_PATH));
      }
    
    public void restorePrivateKey (GenKey key, PrivateKey private_key) throws IOException, GeneralSecurityException
      {
        MacGenerator privk_mac = key.getEECertMacBuilder ();
        byte[] encrypted_private_key = server_sess_key.encrypt (private_key.getEncoded ());
        privk_mac.addArray (encrypted_private_key);
        sks.restorePrivateKey (key.key_handle,
                               encrypted_private_key,
                               mac4call (privk_mac.getResult (), SecureKeyStore.METHOD_RESTORE_PRIVATE_KEY));
      }

    public void postDeleteKey (GenKey key) throws IOException, GeneralSecurityException
      {
        MacGenerator upd_mac = new MacGenerator ();
        byte[] authorization = key.getPostProvMac (upd_mac, this);
        sks.pp_deleteKey (provisioning_handle, key.key_handle, authorization, mac4call (upd_mac.getResult (), SecureKeyStore.METHOD_PP_DELETE_KEY));
      }

    public void postUnlockKey (GenKey key) throws IOException, GeneralSecurityException
      {
        MacGenerator upd_mac = new MacGenerator ();
        byte[] authorization = key.getPostProvMac (upd_mac, this);
        sks.pp_unlockKey (provisioning_handle, key.key_handle, authorization, mac4call (upd_mac.getResult (), SecureKeyStore.METHOD_PP_UNLOCK_KEY));
      }
  
    public boolean exists () throws SKSException
      {
        EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
        while ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), false)) != null)
          {
            if (eps.getProvisioningHandle () == provisioning_handle)
              {
                return true;
              }
          }
        return false;
      }

    protected void finalize() throws Throwable
      {
        abortSession ();
      }

    public byte[] getDeviceID () throws GeneralSecurityException
      {
        return privacy_enabled ? SecureKeyStore.KDF_ANONYMOUS : device.device_info.getCertificatePath ()[0].getEncoded ();
      }

  }
