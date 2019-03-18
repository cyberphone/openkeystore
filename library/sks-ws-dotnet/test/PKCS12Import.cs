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
namespace org.webpki.sks.ws.test
{

using org.webpki.sks.ws.client;


public class PKCS12Import
  {
    public static void Main (string[] argc)
      {
        if (argc.length != 2 && argc.length != 7)
          {
            System.out.println ("\nUsage: " + PKCS12Import.class.getCanonicalName () + 
                                " file password [pin format imputmethod grouping appusage]");
            System.exit (-3);
          }
        string pin = null;
        AppUsage app_usage = AppUsage.UNIVERSAL;
        PassphraseFormat format = null;
        InputMethod input_method = null;
        Grouping grouping = null;
        string[] endorsed_algs = new string[0];
        if (argc.length > 2)
          {
            pin = argc[2];
            format = PassphraseFormat.valueOf (argc[3]);
            input_method = InputMethod.valueOf (argc[4]);
            grouping = Grouping.valueOf (argc[5]);
            app_usage = AppUsage.valueOf (argc[6]);
          }
        char[] password = argc[1].toCharArray ();
        Security.insertProviderAt (new BouncyCastleProvider(), 1);
        KeyStore ks = KeyStore.getInstance ("PKCS12");
        ks.load (new FileInputStream (argc[0]), password);
        Vector<X509Certificate> cert_path = new Vector<X509Certificate> ();
        PrivateKey private_key = null;
        Enumeration<string> aliases = ks.aliases ();
        while (aliases.hasMoreElements ())
          {
            string alias = aliases.nextElement ();
            if (ks.isKeyEntry (alias))
              {
                private_key = (PrivateKey) ks.getKey (alias, password);
                for (Certificate cert : ks.getCertificateChain (alias))
                  {
                    cert_path.add ((X509Certificate) cert);
                  }
                break;
              }
          }
        boolean rsa_flag = cert_path.firstElement ().getPublicKey () instanceof RSAPublicKey;
        if (private_key == null)
          {
            throw new IOException ("No private key!");
          }
        if (app_usage == AppUsage.ENCRYPTION)
          {
            endorsed_algs = new string[]{rsa_flag ? 
                    AsymEncryptionAlgorithms.RSA_PKCS_1.getURI ()
                                                  :
                    KeyGen2URIs.ALGORITHMS.ECDH_RAW};
          }
        else if (app_usage == AppUsage.SIGNATURE)
          {
            endorsed_algs = rsa_flag ? 
                    new string[]{SignatureAlgorithms.RSA_SHA1.getURI (), SignatureAlgorithms.RSA_SHA256.getURI ()}
                                     :
                    new string[]{SignatureAlgorithms.ECDSA_SHA256.getURI ()};
          }
        SecureKeyStore sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.client")).newInstance ();
        EnumeratedKey ek = new EnumeratedKey ();
        GenKey old_key = null;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (sks.getKeyAttributes (ek.getKeyHandle ()).getCertificatePath ()[0].equals (cert_path.get (0)))
              {
                System.out.println ("Duplicate entry - Replace key #" + ek.getKeyHandle ());
                EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
                while ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), false)) != null)
                  {
                    if (eps.getProvisioningHandle () == ek.getProvisioningHandle ())
                      {
                        PublicKey kmk = eps.getKeyManagementKey ();
                        if (kmk != null && new ProvSess.SoftHSM ().enumerateKeyManagementKeys ()[0].equals (kmk))
                          {
                            old_key = new GenKey ();
                            old_key.key_handle = ek.getKeyHandle ();
                            old_key.cert_path = cert_path.toArray (new X509Certificate[0]);
                            if (sks instanceof WSSpecific)
                              {
                                 ((WSSpecific)sks).logEvent ("Updating");
                              }
                          }
                        break;
                      }
                  }
                break;
              }
          }
        Device device = new Device (sks);
        ProvSess sess = new ProvSess (device, 0);
        if (old_key != null)
          {
            sess.postDeleteKey (old_key);
          }
        PINPol pin_policy = null;
        string prot = "NO PIN";
        if (argc.length > 2)
          {
            pin = argc[2];
            sess.setInputMethod (input_method);
            prot ="PIN [Format=" + format + ", InputMode=" + input_method + ", Grouping=" + grouping + ", AppUsage=" + app_usage + "]";
            pin_policy = sess.createPINPolicy ("PIN",
                                               format,
                                               EnumSet.noneOf (PatternRestriction.class),
                                               grouping,
                                               1 /* min_length */, 
                                               50 /* max_length */,
                                               (short) 3 /* retry_limit*/, 
                                               null /* puk_policy */);
          }
        GenKey key = sess.createECKey ("Key",
                                       pin /* pin_value */,
                                       pin_policy /* pin_policy */,
                                       app_usage,
                                       endorsed_algs);
        GenKey key = sess.createKey ("Key",
                                     KeyGen2URIs.ALGORITHMS.KEY_ATTESTATION_1,
			                         null /* server_seed */,
            		                 pin_policy,
               			             pin,
                                     BiometricProtection.NONE /* biometric_protection */,
                                     ExportProtection.NON_EXPORTABLE /* export_policy */,
                                     DeleteProtection.NONE /* delete_policy */,
                                     false /* enable_pin_caching */,
                                     app_usage,
                          "" /* friendly_name */,
                          new KeySpecifier.EC (ECDomains.P_256),
                          endorsed_algs);
        key.setCertificatePath (cert_path.toArray (new X509Certificate[0]));
        key.restorePrivateKey (private_key);
        sess.closeSession ();
        System.out.println ("Imported Subject: " + cert_path.firstElement ().getSubjectX500Principal ().getName () + "\nID=#" + key.key_handle +
                            ", "+ (rsa_flag ? "RSA" : "EC") + " Key with " + prot);
      }
  }
  
}
