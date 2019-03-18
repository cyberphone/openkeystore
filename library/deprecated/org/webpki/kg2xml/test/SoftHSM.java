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
package org.webpki.kg2xml.test;

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

import java.util.LinkedHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.kg2xml.ServerCryptoInterface;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

public class SoftHSM implements ServerCryptoInterface
  {
    private static final long serialVersionUID = 1L;
  
    ////////////////////////////////////////////////////////////////////////////////////////
    // Private and secret keys would in a HSM implementation be represented as handles
    ////////////////////////////////////////////////////////////////////////////////////////
    LinkedHashMap<PublicKey,PrivateKey> key_management_keys = new LinkedHashMap<PublicKey,PrivateKey> ();
    
    private void addKMK (KeyStore km_keystore) throws IOException, GeneralSecurityException
      {
        key_management_keys.put (km_keystore.getCertificate ("mykey").getPublicKey (),
                                 (PrivateKey) km_keystore.getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
      }
    
    public SoftHSM () throws IOException, GeneralSecurityException
      {
        addKMK (DemoKeyStore.getMybankDotComKeyStore ());
        addKMK (DemoKeyStore.getSubCAKeyStore ());
        addKMK (DemoKeyStore.getECDSAStore ());
      }
    
    ECPrivateKey server_ec_private_key;
    
    byte[] session_key;
  
    @Override
    public ECPublicKey generateEphemeralKey (KeyAlgorithms ec_key_algorithm) throws IOException
      {
        try
          {
            KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec (ec_key_algorithm.getJCEName ());
            generator.initialize (eccgen, new SecureRandom ());
            KeyPair kp = generator.generateKeyPair();
            server_ec_private_key = (ECPrivateKey) kp.getPrivate ();
            return (ECPublicKey) kp.getPublic ();
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
  
    @Override
    public void generateAndVerifySessionKey (ECPublicKey client_ephemeral_key,
                                             byte[] kdf_data,
                                             byte[] attestation_arguments,
                                             X509Certificate device_certificate,
                                             byte[] session_attestation) throws IOException
      {
        try
          {
            // SP800-56A C(2, 0, ECC CDH)
            KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
            key_agreement.init (server_ec_private_key);
            key_agreement.doPhase (client_ephemeral_key, true);
            byte[] Z = key_agreement.generateSecret ();
      
            // The custom KDF
            Mac mac = Mac.getInstance (MACAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (Z, "RAW"));
            session_key = mac.doFinal (kdf_data);
            
            if (device_certificate == null)
              {
                // Privacy enabled mode
                mac = Mac.getInstance (MACAlgorithms.HMAC_SHA256.getJCEName ());
                mac.init (new SecretKeySpec (session_key, "RAW"));
                byte[] session_key_attest = mac.doFinal (attestation_arguments);
                
                // Verify that the session key signature is correct
                if (!ArrayUtil.compare (session_key_attest, session_attestation))
                  {
                    throw new IOException ("Verify attestation failed");
                  }
              }
            else
              {
                // E2ES mode
                PublicKey device_public_key = device_certificate.getPublicKey ();
                AsymSignatureAlgorithms signatureAlgorithm = device_public_key instanceof RSAPublicKey ?
                    AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256;
      
                // Verify that attestation was signed by the device key
                Signature verifier = Signature.getInstance (signatureAlgorithm.getJCEName ());
                verifier.initVerify (device_public_key);
                verifier.update (attestation_arguments);
                if (!verifier.verify (session_attestation))
                  {
                    throw new IOException ("Verify provisioning signature failed");
                  }
              }
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
  
    @Override
    public byte[] mac (byte[] data, byte[] key_modifier) throws IOException
      {
        try
          {
            Mac mac = Mac.getInstance (MACAlgorithms.HMAC_SHA256.getJCEName ());
            mac.init (new SecretKeySpec (ArrayUtil.add (session_key, key_modifier), "RAW"));
            return mac.doFinal (data);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
  
    @Override
    public byte[] encrypt (byte[] data) throws IOException
      {
        try
          {
            byte[] key = mac (SecureKeyStore.KDF_ENCRYPTION_KEY, new byte[0]);
            Cipher crypt = Cipher.getInstance ("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom ().nextBytes (iv);
            crypt.init (Cipher.ENCRYPT_MODE, new SecretKeySpec (key, "AES"), new IvParameterSpec (iv));
            return ArrayUtil.add (iv, crypt.doFinal (data));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
  
    @Override
    public byte[] generateNonce () throws IOException
      {
        byte[] rnd = new byte[32];
        new SecureRandom ().nextBytes (rnd);
        return rnd;
      }
  
    @Override
    public byte[] generateKeyManagementAuthorization (PublicKey key_management__key, byte[] data) throws IOException
      {
        try
          {
            Signature km_sign = Signature.getInstance (key_management__key instanceof RSAPublicKey ? "SHA256WithRSA" : "SHA256WithECDSA");
            km_sign.initSign (key_management_keys.get (key_management__key));
            km_sign.update (data);
            return km_sign.sign ();
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
  
    @Override
    public PublicKey[] enumerateKeyManagementKeys () throws IOException
      {
        return key_management_keys.keySet ().toArray (new PublicKey[0]);
      }
  }
