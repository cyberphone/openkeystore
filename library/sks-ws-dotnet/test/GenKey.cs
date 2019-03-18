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


public class GenKey
  {
    String id;
    int key_handle;
    PublicKey public_key;
    X509Certificate[] cert_path;
    ProvSess prov_sess;
    
    public GenKey setCertificate (String dn) throws IOException, GeneralSecurityException
      {
        return setCertificate (dn, public_key);
      }

    public GenKey setCertificate (String dn, PublicKey public_key) throws IOException, GeneralSecurityException
      {
        CertSpec cert_spec = new CertSpec ();
        cert_spec.setEndEntityConstraint ();
        cert_spec.setSubject (dn);

        GregorianCalendar start = new GregorianCalendar ();
        GregorianCalendar end = (GregorianCalendar) start.clone ();
        end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);
    
        X509Certificate certificate = 
            new CA ().createCert (cert_spec,
                                  DistinguishedName.subjectDN ((X509Certificate)DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")),
                                  new BigInteger (String.valueOf (new Date ().getTime ())),
                                  start.getTime (),
                                  end.getTime (), 
                                  SignatureAlgorithms.RSA_SHA256,
                                  new AsymKeySignerInterface ()
            {
    
              @Override
              public PublicKey getPublicKey () throws IOException, GeneralSecurityException
                {
                  return ((X509Certificate)DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")).getPublicKey ();
                }
    
              @Override
              public byte[] signData (byte[] data, SignatureAlgorithms algorithm) throws IOException, GeneralSecurityException
                {
                  Signature signer = Signature.getInstance (algorithm.getJCEName ());
                  signer.initSign ((PrivateKey) DemoKeyStore.getSubCAKeyStore ().getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
                  signer.update (data);
                  return signer.sign ();
                }
              
            }, public_key);
        return setCertificatePath (new X509Certificate[]{certificate});
      }
    
    public GenKey setCertificatePath (X509Certificate[] cert_path) throws IOException, GeneralSecurityException
      {
        this.cert_path = cert_path;
        prov_sess.setCertificate (key_handle, id, public_key, cert_path);
        return this;
      }
    
    public PublicKey getPublicKey ()
      {
        return cert_path == null ? public_key : cert_path[0].getPublicKey ();
      }

    public X509Certificate[] getCertificatePath ()
      {
        return cert_path;
      }
    
    void setSymmetricKey (byte[] symmetric_key) throws IOException, GeneralSecurityException
      {
        MacGenerator symk_mac = getEECertMacBuilder ();
        byte[] encrypted_symmetric_key = prov_sess.server_sess_key.encrypt (symmetric_key);
        symk_mac.addArray (encrypted_symmetric_key);
        prov_sess.sks.setSymmetricKey (key_handle, encrypted_symmetric_key, prov_sess.mac4call (symk_mac.getResult (), SecureKeyStore.METHOD_SET_SYMMETRIC_KEY));
      }

    void restorePrivateKey (PrivateKey private_key) throws IOException, GeneralSecurityException
      {
        MacGenerator privk_mac = getEECertMacBuilder ();
        byte[] encrypted_private_key = prov_sess.server_sess_key.encrypt (private_key.getEncoded ());
        privk_mac.addArray (encrypted_private_key);
        prov_sess.sks.restorePrivateKey (key_handle, encrypted_private_key, prov_sess.mac4call (privk_mac.getResult (), SecureKeyStore.METHOD_RESTORE_PRIVATE_KEY));
      }

    public byte[] getPostProvMac (MacGenerator upd_mac, ProvSess current) throws IOException, GeneralSecurityException
      {
        Integer kmk_id = current.kmk_id;
        if (kmk_id == null)
          {
            kmk_id = 0;  // Just for JUnit...
          }
        PublicKey kmk = current.server_sess_key.enumerateKeyManagementKeys ()[kmk_id];
        byte[] authorization = current.server_sess_key.generateKeyManagementAuthorization (kmk, current.mac (cert_path[0].getEncoded (),
                                                                                                  current.getDeviceID ()));
        upd_mac.addArray (authorization);
        return authorization;
      }
    
    ProvSess.MacGenerator getEECertMacBuilder () throws CertificateEncodingException, IOException
      {
        ProvSess.MacGenerator ee_mac = new ProvSess.MacGenerator ();
        ee_mac.addArray (cert_path[0].getEncoded ());
        return ee_mac;
      }

    public boolean exists () throws SKSException
      {
        EnumeratedKey ek = new EnumeratedKey ();
        while ((ek = prov_sess.sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getKeyHandle () == key_handle)
              {
                return true;
              }
          }
        return false;
      }

    public EnumeratedKey getUpdatedKeyInfo () throws SKSException
      {
        EnumeratedKey ek = new EnumeratedKey ();
        while ((ek = prov_sess.sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getKeyHandle () == key_handle)
              {
                return ek;
              }
          }
        throw new SKSException ("Bad state");
      }
    
    public KeyProtectionInfo getKeyProtectionInfo() throws SKSException
      {
        return prov_sess.sks.getKeyProtectionInfo (key_handle);
      }
    
    public void changePin (String old_pin, String new_pin) throws SKSException, IOException
      {
        prov_sess.sks.changePIN (key_handle, old_pin.getBytes ("UTF-8"), new_pin.getBytes ("UTF-8"));
      }
    
    public byte[] signData (SignatureAlgorithms alg_id, String pin, byte[] data) throws IOException
      {
        return prov_sess.sks.signHashedData (key_handle,
                                             alg_id.getURI (),
                                             null,
                                             pin == null ? null : pin.getBytes ("UTF-8"),
                                             alg_id.getDigestAlgorithm ().digest (data));
      }

    public byte[] asymmetricKeyDecrypt (AsymEncryptionAlgorithms alg_id, String pin, byte[] data) throws IOException
      {
        return prov_sess.sks.asymmetricKeyDecrypt (key_handle,
                                                   alg_id.getURI (), 
                                                   null,
                                                   pin == null ? null : pin.getBytes ("UTF-8"), 
                                                   data);
      }

    public byte[] symmetricKeyEncrypt (SymEncryptionAlgorithms alg_id, boolean mode, byte[] iv, String pin, byte[] data) throws IOException
      {
        return prov_sess.sks.symmetricKeyEncrypt (key_handle,
                                                  alg_id.getURI (),
                                                  mode,
                                                  iv,
                                                  pin == null ? null : pin.getBytes ("UTF-8"),
                                                  data);
      }

    public byte[] performHMAC (MacAlgorithms alg_id, String pin, byte[] data) throws IOException
      {
        return prov_sess.sks.performHMAC (key_handle,
                                          alg_id.getURI (),
                                          pin == null ? null : pin.getBytes ("UTF-8"),
                                          data);
      }

    public void postUpdateKey (GenKey target_key) throws IOException, GeneralSecurityException
      {
        MacGenerator upd_mac = getEECertMacBuilder ();
        byte[] authorization = target_key.getPostProvMac (upd_mac, prov_sess);
        prov_sess.sks.pp_updateKey (key_handle, 
                                    target_key.key_handle,
                                    authorization,
                                    prov_sess.mac4call (upd_mac.getResult (), SecureKeyStore.METHOD_PP_UPDATE_KEY));
      }
  
    public void postCloneKey (GenKey target_key) throws IOException, GeneralSecurityException
      {
        MacGenerator upd_mac = getEECertMacBuilder ();
        byte[] authorization = target_key.getPostProvMac (upd_mac, prov_sess);
        prov_sess.sks.pp_cloneKeyProtection (key_handle, 
                                             target_key.key_handle,
                                             authorization,
                                             prov_sess.mac4call (upd_mac.getResult (), SecureKeyStore.METHOD_PP_CLONE_KEY_PROTECTION));
      }

  }
