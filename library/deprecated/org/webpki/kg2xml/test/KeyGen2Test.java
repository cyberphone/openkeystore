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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Vector;

import javax.crypto.KeyAgreement;
import javax.security.auth.x500.X500Principal;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.rules.TestName;

import static org.junit.Assert.*;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.kg2xml.Action;
import org.webpki.kg2xml.BasicCapabilities;
import org.webpki.kg2xml.CredentialDiscoveryRequestDecoder;
import org.webpki.kg2xml.CredentialDiscoveryRequestEncoder;
import org.webpki.kg2xml.CredentialDiscoveryResponseDecoder;
import org.webpki.kg2xml.CredentialDiscoveryResponseEncoder;
import org.webpki.kg2xml.KeyCreationRequestDecoder;
import org.webpki.kg2xml.KeyCreationRequestEncoder;
import org.webpki.kg2xml.KeyCreationResponseDecoder;
import org.webpki.kg2xml.KeyCreationResponseEncoder;
import org.webpki.kg2xml.KeyGen2Constants;
import org.webpki.kg2xml.KeyGen2URIs;
import org.webpki.kg2xml.KeySpecifier;
import org.webpki.kg2xml.PlatformNegotiationRequestDecoder;
import org.webpki.kg2xml.PlatformNegotiationRequestEncoder;
import org.webpki.kg2xml.PlatformNegotiationResponseDecoder;
import org.webpki.kg2xml.PlatformNegotiationResponseEncoder;
import org.webpki.kg2xml.ProvisioningFinalizationRequestDecoder;
import org.webpki.kg2xml.ProvisioningFinalizationRequestEncoder;
import org.webpki.kg2xml.ProvisioningFinalizationResponseDecoder;
import org.webpki.kg2xml.ProvisioningFinalizationResponseEncoder;
import org.webpki.kg2xml.ProvisioningInitializationRequestDecoder;
import org.webpki.kg2xml.ProvisioningInitializationRequestEncoder;
import org.webpki.kg2xml.ProvisioningInitializationResponseDecoder;
import org.webpki.kg2xml.ProvisioningInitializationResponseEncoder;
import org.webpki.kg2xml.ServerState;

import org.webpki.sks.AppUsage;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.KeyData;
import org.webpki.sks.Grouping;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.Property;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.sks.ws.WSSpecific;

import org.webpki.tools.XML2HTMLPrinter;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HTMLHeader;
import org.webpki.util.ImageData;

import org.webpki.xml.XMLSchemaCache;
import org.webpki.xml.XMLObjectWrapper;

/*
 * KeyGen2 "Protocol Exerciser" / JUnit Test
 */
public class KeyGen2Test
  {
    static final byte[] TEST_STRING = {'S','u','c','c','e','s','s',' ','o','r',' ','n','o','t','?'};

    boolean pin_protection;
    
    boolean ecc_key;
    
    boolean two_keys;
    
    boolean key_agreement;
    
    boolean serverSeed;
    
    boolean propertyBag;
    
    boolean symmetricKey;
    
    boolean updatable;
    
    boolean ecc_kmk;
    
    boolean fixed_pin;
    
    Server clone_key_protection;
    
    Server update_key;
    
    Server delete_key;
    
    Server plain_unlock_key;
    
    boolean devicePinProtection;
    
    boolean enablePinCaching;
    
    boolean privacy_enabled;
    
    boolean pin_group_shared;
    
    boolean puk_protection;
    
    boolean add_pin_pattern;
    
    boolean presetPin;
    
    boolean encryption_key;
    
    boolean set_private_key;
    
    boolean set_logotype;
    
    boolean encryptedExtension;
    
    boolean set_trust_anchor;
    
    boolean update_kmk;
    
    boolean virtual_machine;
    
    boolean brain_pool;
    
    boolean get_client_attributes;
    
    boolean https;  // Use server-cert
    
    boolean ask_for_4096;
    
    boolean ask_for_exponent;
    
    boolean set_abort_url;
    
    ExportProtection exportProtection;
    
    DeleteProtection deleteProtection;
    
    InputMethod inputMethod;
    
    boolean image_prefs;
    
    static FileOutputStream fos;
    
    static SecureKeyStore sks;
    
    static final byte[] OTP_SEED = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};
    
    static final byte[] AES32BITKEY = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    
    static final byte[] USER_DEFINED_PIN = {'0','1','5','3','5','4'};

    static final byte[] PREDEF_SERVER_PIN = {'3','1','2','5','8','9'};
    
    static final byte[] BAD_PIN = {0x03, 0x33, 0x03, 0x04};

    static final String ABORT_URL = "http://issuer.example.com/abort";

    static final String PLATFORM_URL = "http://issuer.example.com/platform";

    static final String ISSUER_URL = "http://issuer.example.com/provsess";
    
    static final String KEY_INIT_URL = "http://issuer.example.com/keyinit";

    static final String FIN_PROV_URL = "http://issuer.example.com/finalize";

    static final String CRE_DISC_URL = "http://issuer.example.com/credisc";
    
    static final String ACME_INDUSTRIES = "Acme Industries";
    
    static final String SPECIFIC_VM = "http://platforms.extreme-vm.com/type.3";
    static final String FOR_THE_CLIENT_UNKNOWN_VM = "http://cool-but-obscure-vm.com/x";
    static final byte[] VM_CONFIG_DATA = {0,1,2,3};  // In real file probably a bit bigger...
    
    static X509Certificate server_certificate;
    
    int round;
   
    @BeforeClass
    public static void openFile () throws Exception
      {
        String dir = System.getProperty ("testout.dir");
        if (dir.length () > 0)
          {
            fos = new FileOutputStream (dir + "/kg2xml.junit.run.html");
            fos.write (HTMLHeader.createHTMLHeader (false, true,"KeyGen2 JUinit test output", null).append ("<body><h3>KeyGen2 JUnit Test</h3><p>").toString ().getBytes ("UTF-8"));
          }
        CustomCryptoProvider.forcedLoad ();
        server_certificate = (X509Certificate) CertificateFactory.getInstance ("X.509").generateCertificate (KeyGen2Test.class.getResourceAsStream ("server-certificate.der"));
        sks = (SecureKeyStore) Class.forName (System.getProperty ("sks.implementation")).newInstance ();
        if (fos != null)
          {
            DeviceInfo dev = sks.getDeviceInfo ();
            fos.write (("<b>SKS Description: " + dev.getVendorDescription () +
                        "<br>SKS Vendor: " + dev.getVendorName () +
                        "<br>SKS API Level: " + (dev.getAPILevel () / 100) + '.' + (dev.getAPILevel () % 100) +
                        "<br>SKS Interface: " + (sks instanceof WSSpecific ? "WebService" : "Direct") +
                        "<br>&nbsp<br></b>").getBytes ("UTF-8"));
          }
        if (sks instanceof WSSpecific)
          {
            String deviceId = System.getProperty ("sks.device");
            if (deviceId != null && deviceId.length () != 0)
              {
                ((WSSpecific) sks).setDeviceID (deviceId);
              }
          }
      }

    @AfterClass
    public static void closeFile () throws Exception
      {
        if (fos != null)
          {
            fos.write ("</body></html>".getBytes ("UTF-8"));
            fos.close ();
          }
      }
    
    @Before
    public void setup () throws Exception
      {
         if (sks instanceof WSSpecific)
           {
             ((WSSpecific)sks).logEvent ("Testing:" + _name.getMethodName ());
           }
      }
        
    @After
    public void teardown () throws Exception
      {
      }
    @Rule 
    public TestName _name = new TestName();
    
    static class KeyCreator
      {
        private static final String kg2keycre = 
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
          "<KeyCreationRequest " + KeyGen2Constants.KEY_ENTRY_ALGORITHM_ATTR  + "=\"http://xmlns.webpki.org/sks/algorithm#key.1\" " +
          "ClientSessionID=\"C-139622a0ac98f2f44a35c9753ca\" " +
          "ID=\"S-139622a0a9993085d38d1586b76\" " +
          "SubmitURL=\"http://issuer.example.com/keyinit\" " +
          "xmlns=\"" + KeyGen2Constants.KEYGEN2_NS + "\">";
      
        private static XMLSchemaCache xml_cache;
        
        static
        {
          try
            {
              xml_cache = new XMLSchemaCache ();
              xml_cache.addWrapper (KeyCreationRequestDecoder.class);
            }
          catch (IOException e)
            {
            }
        }
        
        private StringBuilder xml = new StringBuilder (kg2keycre);
        
        private int keyId;
        
        private int pin_id;
        
        private boolean pin_active;
        
        KeyCreator () throws IOException
          {
          }
        
        KeyCreator addPIN (PassphraseFormat format, Grouping grouping, PatternRestriction[] patterns)
          {
            finishPIN ();
            pin_active = true;
            if (grouping == null)
              {
                grouping = Grouping.NONE;
              }
            xml.append ("<" + KeyGen2Constants.PIN_POLICY_SPECIFIER_ELEM + " Format=\"")
               .append (format.getProtocolName ())
               .append ("\" ID=\"PIN.")
               .append (++pin_id)
               .append ("\" Grouping=\"")
               .append (grouping.getProtocolName ())
               .append ("\"");
            if (patterns != null)
              {
                xml.append (" PatternRestrictions=\"");
                String blank="";
                for (PatternRestriction pattern : patterns)
                  {
                    xml.append (blank);
                    blank = " ";
                    xml.append (pattern.getProtocolName ());
                  }
                xml.append ("\"");
              }
            xml.append (" MAC=\"3dGegeDJ1enpEzCgwdbXJirNZ95wooM6ordOGW/AJ+0=\" MaxLength=\"8\" MinLength=\"4\" RetryLimit=\"3\">");
            return this;
          }
        
        private void finishPIN ()
          {
            if (pin_active)
              {
                pin_active = false;
                xml.append ("</" + KeyGen2Constants.PIN_POLICY_SPECIFIER_ELEM + ">");
              }
          }

        KeyCreator addKey (AppUsage appUsage)
          {
            xml.append ("<" + KeyGen2Constants.KEY_ENTRY_SPECIFIER_ELEM + " AppUsage=\"")
               .append (appUsage.getProtocolName ())
               .append ("\" ID=\"Key.")
               .append (++keyId)
               .append ("\" KeyAlgorithm=\"http://xmlns.webpki.org/sks/algorithm#rsa2048\" MAC=\"Jrqigi79Yw6SoLobsBA5S8b74gTKrIJPh3tQRKci33Y=\"/>");
            return this;
          }

        KeyCreationRequestDecoder parse () throws Exception
          {
            finishPIN ();
            return (KeyCreationRequestDecoder)xml_cache.parse (xml.append ("</KeyCreationRequest>").toString ().getBytes ("UTF-8"));
          }
      }

    boolean PINCheck (PassphraseFormat format, PatternRestriction[] patterns, String pin) throws Exception
      {
        KeyCreator kc = new KeyCreator ();
        kc.addPIN (format, null, patterns);
        kc.addKey (AppUsage.AUTHENTICATION);
        KeyCreationRequestDecoder.UserPINDescriptor upd = kc.parse ().getUserPINDescriptors ().elementAt (0);
        KeyCreationRequestDecoder.UserPINError pin_test = upd.setPIN (pin, false);
        KeyCreationRequestDecoder.UserPINError pin_set = upd.setPIN (pin, true);
        if ((pin_test == null) ^ (pin_set == null))
          {
            throw new IOException ("PIN test/set confusion");
          }
        return pin_set == null;
      }
    
    void PINGroupCheck (Grouping grouping, AppUsage[] keys, String[] pins, int[] index, boolean fail) throws Exception
      {
        KeyCreator kc = new KeyCreator ();
        kc.addPIN (PassphraseFormat.NUMERIC, grouping, null);
        for (AppUsage appUsage : keys)
          {
            kc.addKey (appUsage);
          }
        KeyCreationRequestDecoder decoder = kc.parse ();
        String error = null;
        if (decoder.getUserPINDescriptors ().size () != pins.length)
          {
            error = "Wrong number of PINs";
          }
        else
          {
            int i = 0;
            for (KeyCreationRequestDecoder.UserPINDescriptor upd : decoder.getUserPINDescriptors ())
              {
                if (upd.setPIN (pins[i++], true) != null)
                  {
                    error = "PIN return error";
                    break;
                  }
              }
            if (error == null)
              {
                i = 0;
                for (KeyCreationRequestDecoder.KeyObject ko : decoder.getKeyObjects ())
                  {
                    if (!ArrayUtil.compare (ko.getSKSPINValue (), pins[index[i++]].getBytes ("UTF-8")))
                      {
                        error = "Grouping problem";
                        break;
                      }
                  }
              }
          }
        if (error == null)
          {
            if (fail) throw new IOException ("Error expected");
          }
        else if (!fail)
          {
            throw new IOException ("Unexpected error: " + error);
          }
      }

    class Client
      {
        XMLSchemaCache client_xml_cache;
        
        int provisioning_handle;
        
        KeyCreationRequestDecoder key_creation_request;
        
        ProvisioningInitializationRequestDecoder prov_sess_req;
        
        PlatformNegotiationRequestDecoder platform_req;

        CredentialDiscoveryRequestDecoder cre_disc_req;
        
        DeviceInfo device_info;
        
        Client () throws IOException
          {
            client_xml_cache = new XMLSchemaCache ();
            client_xml_cache.addWrapper (PlatformNegotiationRequestDecoder.class);
            client_xml_cache.addWrapper (ProvisioningInitializationRequestDecoder.class);
            client_xml_cache.addWrapper (CredentialDiscoveryRequestDecoder.class);
            client_xml_cache.addWrapper (KeyCreationRequestDecoder.class);
            client_xml_cache.addWrapper (ProvisioningFinalizationRequestDecoder.class);
          }

        private void abort (String message) throws IOException, SKSException
          {
            sks.abortProvisioningSession (provisioning_handle);
            throw new IOException (message);
          }
        
        private void scanForKeyManagementKeyUpdates (ProvisioningInitializationRequestDecoder.KeyManagementKeyUpdateHolder kmk) throws SKSException
          {
            for (ProvisioningInitializationRequestDecoder.KeyManagementKeyUpdateHolder child : kmk.KeyManagementKeyUpdateHolders ())
              {
                scanForKeyManagementKeyUpdates (child);
                EnumeratedProvisioningSession old_provisioning_session = new EnumeratedProvisioningSession ();
                while ((old_provisioning_session = sks.enumerateProvisioningSessions (old_provisioning_session.getProvisioningHandle (), false)) != null)
                  {
                    if (child.getKeyManagementKey ().equals (old_provisioning_session.getKeyManagementKey ()))
                      {
                        sks.updateKeyManagementKey (old_provisioning_session.getProvisioningHandle (),
                                                    kmk.getKeyManagementKey (),
                                                    child.getAuthorization ());
                      }
                  }
              }
          }

        private void postProvisioning (ProvisioningFinalizationRequestDecoder.PostOperation postOperation, int handle) throws IOException, GeneralSecurityException
          {
            EnumeratedProvisioningSession old_provisioning_session = new EnumeratedProvisioningSession ();
            while (true)
              {
                if ((old_provisioning_session = sks.enumerateProvisioningSessions (old_provisioning_session.getProvisioningHandle (), false)) == null)
                  {
                    abort ("Old provisioning session not found:" + 
                           postOperation.getClientSessionId () + "/" +
                           postOperation.getServerSessionId ());
                  }
                if (old_provisioning_session.getClientSessionId ().equals(postOperation.getClientSessionId ()) &&
                    old_provisioning_session.getServerSessionId ().equals (postOperation.getServerSessionId ()))
                  {
                    break;
                  }
              }
            EnumeratedKey ek = new EnumeratedKey ();
            while (true)
              {
                if ((ek = sks.enumerateKeys (ek.getKeyHandle ())) == null)
                  {
                    abort ("Old key not found");
                  }
                if (ek.getProvisioningHandle () == old_provisioning_session.getProvisioningHandle ())
                  {
                    KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                    if (ArrayUtil.compare (HashAlgorithms.SHA256.digest (ka.getCertificatePath ()[0].getEncoded ()), postOperation.getCertificateFingerprint ()))
                      {
                        switch (postOperation.getPostOperation ())
                          {
                            case ProvisioningFinalizationRequestDecoder.PostOperation.CLONE_KEY_PROTECTION:
                              sks.postCloneKeyProtection (handle, ek.getKeyHandle (), postOperation.getAuthorization (), postOperation.getMac ());
                              break;

                            case ProvisioningFinalizationRequestDecoder.PostOperation.UPDATE_KEY:
                              sks.postUpdateKey (handle, ek.getKeyHandle (),  postOperation.getAuthorization (), postOperation.getMac ());
                              break;

                            case ProvisioningFinalizationRequestDecoder.PostOperation.UNLOCK_KEY:
                              sks.postUnlockKey (handle, ek.getKeyHandle (),  postOperation.getAuthorization (), postOperation.getMac ());
                              break;

                            default:
                              sks.postDeleteKey (handle, ek.getKeyHandle (), postOperation.getAuthorization (), postOperation.getMac ());
                          }
                        return;
                      }
                  }
              }
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get platform request and respond with SKS compatible data
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] platformResponse (byte[] xmldata) throws IOException
          {
            platform_req = (PlatformNegotiationRequestDecoder) client_xml_cache.parse (xmldata);
            if (set_abort_url)
              {
                assertTrue ("Abort URL", platform_req.getAbortURL ().equals (ABORT_URL));
              }
            else
              {
                assertTrue ("Abort URL", platform_req.getAbortURL () == null);
              }
            device_info = sks.getDeviceInfo ();
            PlatformNegotiationResponseEncoder platform_response = new PlatformNegotiationResponseEncoder (platform_req);
            BasicCapabilities basic_capabilties_response = platform_response.getBasicCapabilities ();
            BasicCapabilities basic_capabilties_request = platform_req.getBasicCapabilities ();
            Vector<String> matches = new Vector<String> ();
            for (String want : basic_capabilties_request.getAlgorithms ())
              {
                for (String have : device_info.getSupportedAlgorithms ())
                  {
                    if (have.equals (want))
                      {
                        matches.add (have);
                        break;
                      }
                  }
              }
            for (String algorithm : matches)
              {
                basic_capabilties_response.addAlgorithm (algorithm);
              }
            for (String client_attribute : basic_capabilties_request.getClientAttributes ())
              {
                if (client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER) || client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS))
                  {
                    basic_capabilties_response.addClientAttribute (client_attribute);
                  }
              }
            if (image_prefs)
              {
                platform_response.addImagePreference (KeyGen2URIs.LOGOTYPES.CARD, "image/png", 200, 120);
              }
            for (String extension : basic_capabilties_request.getExtensions ())
              {
                if (extension.equals (KeyGen2URIs.FEATURE.VIRTUAL_MACHINE))
                  {
                    basic_capabilties_response.addExtension (KeyGen2URIs.FEATURE.VIRTUAL_MACHINE);
                    basic_capabilties_response.addExtension (SPECIFIC_VM);
                    byte[] nonce = new byte[16];
                    new SecureRandom ().nextBytes (nonce);
                    platform_response.setNonce (nonce);
                  }
              }
            return platform_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get provisioning session request and respond with ephemeral keys and and attest
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessResponse (byte[] xmldata) throws IOException
          {
            prov_sess_req = (ProvisioningInitializationRequestDecoder) client_xml_cache.parse (xmldata);
            scanForKeyManagementKeyUpdates (prov_sess_req.getKeyManagementKeyUpdateHolderRoot ());
            assertTrue ("Submit URL", prov_sess_req.getSubmitUrl ().equals (ISSUER_URL));
            assertFalse ("VM", virtual_machine ^ ACME_INDUSTRIES.equals (prov_sess_req.getVirtualMachineFriendlyName ()));
            Date clientTime = new Date ();
            ProvisioningSession sess = 
                  sks.createProvisioningSession (prov_sess_req.getSessionKeyAlgorithm (),
                                                 platform_req.getPrivacyEnabledFlag(),
                                                 prov_sess_req.getServerSessionId (),
                                                 prov_sess_req.getServerEphemeralKey (),
                                                 prov_sess_req.getSubmitUrl (), /* IssuerURI */
                                                 prov_sess_req.getKeyManagementKey (),
                                                 (int)(clientTime.getTime () / 1000),
                                                 prov_sess_req.getSessionLifeTime (),
                                                 prov_sess_req.getSessionKeyLimit ());
            provisioning_handle = sess.getProvisioningHandle ();
            
            ProvisioningInitializationResponseEncoder prov_init_response = 
                  new ProvisioningInitializationResponseEncoder (sess.getClientEphemeralKey (),
                                                                 prov_sess_req.getServerSessionId (),
                                                                 sess.getClientSessionId (),
                                                                 prov_sess_req.getServerTime (),
                                                                 clientTime,
                                                                 sess.getSessionAttestation (),
                                                                 platform_req.getPrivacyEnabledFlag () ? null : device_info.getCertificatePath ());
            if (https)
              {
                prov_init_response.setServerCertificate (server_certificate);
              }

            for (String client_attribute : prov_sess_req.getClientAttributes ())
              {
                if (client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER))
                  {
                    prov_init_response.setClientAttributeValue (client_attribute, "490154203237518");
                  }
                else if (client_attribute.equals (KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS))
                  {
                    prov_init_response.setClientAttributeValue (client_attribute, "fe80::4465:62dc:5fa5:4766%10")
                                      .setClientAttributeValue (client_attribute, "192.168.0.202");
                  }
              }

            prov_init_response.signRequest (new SymKeySignerInterface ()
              {
                public MACAlgorithms getMacAlgorithm () throws IOException
                  {
                    return MACAlgorithms.HMAC_SHA256;
                  }

                public byte[] signData (byte[] data) throws IOException
                  {
                    return sks.signProvisioningSessionData (provisioning_handle, data);
                  }
              });
            return prov_init_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get credential doscovery request
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDiscResponse (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            cre_disc_req = (CredentialDiscoveryRequestDecoder) client_xml_cache.parse (xmldata);
            assertTrue ("Submit URL", cre_disc_req.getSubmitUrl ().equals (CRE_DISC_URL));
            CredentialDiscoveryResponseEncoder cdre = new CredentialDiscoveryResponseEncoder (cre_disc_req);
            for (CredentialDiscoveryRequestDecoder.LookupSpecifier ls : cre_disc_req.getLookupSpecifiers ())
              {
                CredentialDiscoveryResponseEncoder.LookupResult lr = cdre.addLookupResult (ls.getID ());
                EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
                while ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), false)) != null)
                  {
                    if (ls.getKeyManagementKey ().equals (eps.getKeyManagementKey ()))
                      {
                        EnumeratedKey ek = new EnumeratedKey ();
                        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
                          {
                            if (ek.getProvisioningHandle () == eps.getProvisioningHandle ())
                              {
                                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                                X509Certificate[] cert_path = ka.getCertificatePath ();
                                CertificateFilter cf = new CertificateFilter ();
                                cf.setIssuerRegEx (ls.getIssuerRegEx ());
                                cf.setSubjectRegEx (ls.getSubjectRegEx ());
                                cf.setSerialNumber (ls.getSerialNumber ());
                                cf.setEmailRegEx (ls.getEmailRegEx ());
                                cf.setPolicyRules (ls.getPolicyRules ());
                                if (!cf.matches (cert_path))
                                  {
                                    continue;
                                  }
                                lr.addMatchingCredential (cert_path,
                                                          eps.getClientSessionId (),
                                                          eps.getServerSessionId (),
                                                          sks.getKeyProtectionInfo (ek.getKeyHandle ()).isPINBlocked ());
                              }
                          }
                      }
                  }
              }
            return cdre.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get key initialization request and respond with freshly generated public keys
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] keyCreResponse (byte[] xmldata) throws IOException
          {
            key_creation_request = (KeyCreationRequestDecoder) client_xml_cache.parse (xmldata);
            assertTrue ("Submit URL", key_creation_request.getSubmitUrl ().equals (KEY_INIT_URL));
            KeyCreationResponseEncoder key_creation_response = new KeyCreationResponseEncoder (key_creation_request);
            for (KeyCreationRequestDecoder.UserPINDescriptor upd : key_creation_request.getUserPINDescriptors ())
              {
                upd.setPIN (new String (USER_DEFINED_PIN, "UTF-8"), true);
              }
            int pin_policy_handle = 0;
            int puk_policy_handle = 0;
            for (KeyCreationRequestDecoder.KeyObject key : key_creation_request.getKeyObjects ())
              {
                if (key.getPINPolicy () == null)
                  {
                    pin_policy_handle = 0;
                    puk_policy_handle = 0;
                  }
                else
                  {
                    if (key.isStartOfPINPolicy ())
                      {
                        if (key.isStartOfPUKPolicy ())
                          {
                            KeyCreationRequestDecoder.PUKPolicy pukPolicy = key.getPINPolicy ().getPUKPolicy ();
                            puk_policy_handle = sks.createPUKPolicy (provisioning_handle, 
                                                                     pukPolicy.getID (),
                                                                     pukPolicy.getEncryptedValue (),
                                                                     pukPolicy.getFormat ().getSksValue (),
                                                                     pukPolicy.getRetryLimit (),
                                                                     pukPolicy.getMac());
                          }
                        KeyCreationRequestDecoder.PINPolicy pinPolicy = key.getPINPolicy ();
                        pin_policy_handle = sks.createPINPolicy (provisioning_handle,
                                                                 pinPolicy.getID (),
                                                                 puk_policy_handle,
                                                                 pinPolicy.getUserDefinedFlag (),
                                                                 pinPolicy.getUserModifiableFlag (),
                                                                 pinPolicy.getFormat ().getSksValue (),
                                                                 pinPolicy.getRetryLimit (),
                                                                 pinPolicy.getGrouping ().getSksValue (),
                                                                 PatternRestriction.getSksValue (pinPolicy.getPatternRestrictions ()),
                                                                 pinPolicy.getMinLength (),
                                                                 pinPolicy.getMaxLength (),
                                                                 pinPolicy.getInputMethod ().getSksValue (),
                                                                 pinPolicy.getMac ());
                      }
                  }
                KeyData key_data = sks.createKeyEntry (provisioning_handle,
                                                       key.getID (),
                                                       key_creation_request.getKeyEntryAlgorithm (),
                                                       key.getServerSeed (),
                                                       key.isDevicePINProtected (),
                                                       pin_policy_handle,
                                                       key.getSKSPINValue (),
                                                       key.getEnablePINCachingFlag (),
                                                       key.getBiometricProtection ().getSksValue (),
                                                       key.getExportProtection ().getSksValue (),
                                                       key.getDeleteProtection ().getSksValue (),
                                                       key.getAppUsage ().getSksValue (),
                                                       key.getFriendlyName (),
                                                       key.getKeySpecifier ().getKeyAlgorithm ().getURI (),
                                                       key.getKeySpecifier ().getParameters (),
                                                       key.getEndorsedAlgorithms (),
                                                       key.getMac ());
                key_creation_response.addPublicKey (key_data.getPublicKey (),
                                                    key_data.getKeyAttestation (),
                                                    key.getID ());
              }
            return key_creation_response.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Get the certificates and attributes and return a success message
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creFinalizeResponse (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            ProvisioningFinalizationRequestDecoder prov_final_request =
                           (ProvisioningFinalizationRequestDecoder) client_xml_cache.parse (xmldata);
            assertTrue ("Submit URL", prov_final_request.getSubmitUrl ().equals (FIN_PROV_URL));
            /* 
               Note: we could have used the saved provisioning_handle but that would not
               work for certifications that are delayed.  The following code is working
               for fully interactive and delayed scenarios by using SKS as state-holder
            */
            EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession ();
            while (true)
              {
                if ((eps = sks.enumerateProvisioningSessions (eps.getProvisioningHandle (), true)) == null)
                  {
                    abort ("Provisioning session not found:" + 
                           prov_final_request.getClientSessionId () + "/" +
                           prov_final_request.getServerSessionId ());
                  }
                if (eps.getClientSessionId ().equals(prov_final_request.getClientSessionId ()) &&
                    eps.getServerSessionId ().equals (prov_final_request.getServerSessionId ()))
                  {
                    break;
                  }
              }
            
            //////////////////////////////////////////////////////////////////////////
            // Final check, do these keys match the request?
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.IssuedCredential key : prov_final_request.getIssuedKeys ())
              {
                int keyHandle = sks.getKeyHandle (eps.getProvisioningHandle (), key.getID ());
                sks.setCertificatePath (keyHandle, key.getCertificatePath (), key.getMac ());

                //////////////////////////////////////////////////////////////////////////
                // There may be a symmetric key
                //////////////////////////////////////////////////////////////////////////
                if (key.getEncryptedSymmetricKey () != null)
                  {
                    sks.importSymmetricKey (keyHandle, 
                                            key.getEncryptedSymmetricKey (),
                                            key.getSymmetricKeyMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be a private key
                //////////////////////////////////////////////////////////////////////////
                if (key.getEncryptedPrivateKey () != null)
                  {
                    sks.importPrivateKey (keyHandle, 
                                          key.getEncryptedPrivateKey (),
                                          key.getPrivateKeyMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be extensions
                //////////////////////////////////////////////////////////////////////////
                for (ProvisioningFinalizationRequestDecoder.Extension extension : key.getExtensions ())
                  {
                    sks.addExtension (keyHandle,
                                      extension.getExtensionType (),
                                      extension.getSubType (), 
                                      extension.getQualifier (),
                                      extension.getExtensionData (),
                                      extension.getMac ());
                  }

                //////////////////////////////////////////////////////////////////////////
                // There may be an postUpdateKey or postCloneKeyProtection
                //////////////////////////////////////////////////////////////////////////
                ProvisioningFinalizationRequestDecoder.PostOperation postOperation = key.getPostOperation ();
                if (postOperation != null)
                  {
                    postProvisioning (postOperation, keyHandle);
                  }
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of postUnlockKey
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.PostOperation post_unl : prov_final_request.getPostUnlockKeys ())
              {
                postProvisioning (post_unl, eps.getProvisioningHandle ());
              }

            //////////////////////////////////////////////////////////////////////////
            // There may be any number of postDeleteKey
            //////////////////////////////////////////////////////////////////////////
            for (ProvisioningFinalizationRequestDecoder.PostOperation post_del : prov_final_request.getPostDeleteKeys ())
              {
                postProvisioning (post_del, eps.getProvisioningHandle ());
              }

            //////////////////////////////////////////////////////////////////////////
            // Create final and attested message
            //////////////////////////////////////////////////////////////////////////
            ProvisioningFinalizationResponseEncoder fin_prov_response = 
                new ProvisioningFinalizationResponseEncoder (prov_final_request,
                                                             sks.closeProvisioningSession (eps.getProvisioningHandle (),
                                                                                           prov_final_request.getCloseSessionNonce (),
                                                                                           prov_final_request.getCloseSessionMAC ()));
            return fin_prov_response.writeXML ();
          }
      }
    
    class Server
      {
        static final String LOGO_URL = "http://issuer.example.com/images/logo.png";
        static final String LOGO_MIME = "image/png";
        byte[] LOGO_SHA256 = {0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6,0,5,6,6}; 
        static final int LOGO_WIDTH = 200;
        static final int LOGO_HEIGHT = 150;
        
        XMLSchemaCache server_xml_cache;
        
        int pin_retry_limit = 3;

        ServerState serverState;
        
        PrivateKey gen_private_key;
        
        PublicKey server_km;
        
        SoftHSM serverCryptoInterface = new SoftHSM ();

        Server () throws Exception
          {
            server_xml_cache = new XMLSchemaCache ();
            server_xml_cache.addWrapper (PlatformNegotiationResponseDecoder.class);
            server_xml_cache.addWrapper (ProvisioningInitializationResponseDecoder.class);
            server_xml_cache.addWrapper (CredentialDiscoveryResponseDecoder.class);
            server_xml_cache.addWrapper (KeyCreationResponseDecoder.class);
            server_xml_cache.addWrapper (ProvisioningFinalizationResponseDecoder.class);
          }
        
        void getProvSess (XMLObjectWrapper xml_object) throws IOException
          {
            ////////////////////////////////////////////////////////////////////////////////////
            // Begin by creating the "SessionKey" that holds the key to just about everything
            ////////////////////////////////////////////////////////////////////////////////////
            ProvisioningInitializationResponseDecoder prov_init_response = (ProvisioningInitializationResponseDecoder) xml_object;

            ////////////////////////////////////////////////////////////////////////////////////
            // Update the container state.  This is where the action is
            ////////////////////////////////////////////////////////////////////////////////////
            serverState.update (prov_init_response, https ? server_certificate : null);

            ////////////////////////////////////////////////////////////////////////////////////
            // Here we could/should introduce an SKS identity/brand check
            ////////////////////////////////////////////////////////////////////////////////////
            X509Certificate[] certificatePath = prov_init_response.getDeviceCertificatePath ();
          }
        
        //////////////////////////////////////////////////////////////////////////////////
        // Create platform negotiation request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] platformRequest () throws IOException, GeneralSecurityException
          {
            ////////////////////////////////////////////////////////////////////////////////////
            // Create the state container
            ////////////////////////////////////////////////////////////////////////////////////
            serverState = new ServerState (serverCryptoInterface);
            if (privacy_enabled)
              {
                serverState.setPrivacyEnabled (true);
              }
            if (brain_pool)
              {
                serverState.setEphemeralKeyAlgorithm (KeyAlgorithms.BRAINPOOL_P_256);
              }

            ////////////////////////////////////////////////////////////////////////////////////
            // First keygen2 request
            ////////////////////////////////////////////////////////////////////////////////////
            PlatformNegotiationRequestEncoder platform_request =  new PlatformNegotiationRequestEncoder (serverState, PLATFORM_URL, null);
            if (set_abort_url)
              {
                platform_request.setAbortURL (ABORT_URL);
              }
            BasicCapabilities basic_capabilities = platform_request.getBasicCapabilities ();
            if (ask_for_4096)
              {
                basic_capabilities.addAlgorithm (KeyAlgorithms.RSA4096.getURI ())
                                  .addAlgorithm (KeyAlgorithms.RSA2048.getURI ());
              }
            if (ask_for_exponent)
              {
                basic_capabilities.addAlgorithm (KeyAlgorithms.RSA2048_EXP.getURI ());
              }
            if (get_client_attributes)
              {
                basic_capabilities.addClientAttribute (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER)
                                  .addClientAttribute (KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS)
                                  .addClientAttribute (KeyGen2URIs.CLIENT_ATTRIBUTES.MAC_ADDRESS);
              }
            if (plain_unlock_key != null)
              {
                platform_request.setAction (Action.UNLOCK);
              }
            if (virtual_machine)
              {
                basic_capabilities.addExtension (KeyGen2URIs.FEATURE.VIRTUAL_MACHINE);
                basic_capabilities.addExtension (SPECIFIC_VM);
                basic_capabilities.addExtension (FOR_THE_CLIENT_UNKNOWN_VM);
                KeyStoreSigner signer = new KeyStoreSigner (DemoKeyStore.getExampleDotComKeyStore (), null);
                signer.setKey (null, DemoKeyStore.getSignerPassword ());
                platform_request.signRequest (signer);
              }
            return platform_request.writeXML ();
          }

        //////////////////////////////////////////////////////////////////////////////////
        // Create a provisioning session request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] provSessRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            PlatformNegotiationResponseDecoder platform_response = (PlatformNegotiationResponseDecoder) server_xml_cache.parse (xmldata);
            serverState.update (platform_response);
            BasicCapabilities basic_capabilties = platform_response.getBasicCapabilities ();
            if (ask_for_exponent)
              {
                ask_for_exponent = false;
                for (String algorithm : basic_capabilties.getAlgorithms ())
                  {
                    if (algorithm.equals (KeyAlgorithms.RSA2048_EXP.getURI ()))
                      {
                        ask_for_exponent = true;
                      }
                  }
              }
            if (ask_for_4096)
              {
                ask_for_4096 = false;
                for (String algorithm : basic_capabilties.getAlgorithms ())
                  {
                    if (algorithm.equals (KeyAlgorithms.RSA4096.getURI ()))
                      {
                        ask_for_4096 = true;
                      }
                  }
              }

            ProvisioningInitializationRequestEncoder prov_init_request = 
                 new ProvisioningInitializationRequestEncoder (serverState, ISSUER_URL, 10000, (short)50);
            if (updatable)
              {
                ProvisioningInitializationRequestEncoder.KeyManagementKeyUpdateHolder kmk = 
                     prov_init_request.setKeyManagementKey (server_km = serverCryptoInterface.enumerateKeyManagementKeys ()[ecc_kmk ? 2 : 0]);
                if (update_kmk)
                  {
                    kmk.update (serverCryptoInterface.enumerateKeyManagementKeys ()[1])
                       .update (update_key.server_km);
                  }
              }
            if (virtual_machine)
              {
                prov_init_request.setVirtualMachine (VM_CONFIG_DATA, SPECIFIC_VM, ACME_INDUSTRIES);
                KeyStoreSigner signer = new KeyStoreSigner (DemoKeyStore.getExampleDotComKeyStore (), null);
                signer.setKey (null, DemoKeyStore.getSignerPassword ());
                prov_init_request.signRequest (signer);
              }
            return prov_init_request.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create credential discover request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creDiscRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            getProvSess (server_xml_cache.parse (xmldata));
            CredentialDiscoveryRequestEncoder cdre = new CredentialDiscoveryRequestEncoder (serverState, CRE_DISC_URL);
            cdre.addLookupDescriptor (serverCryptoInterface.enumerateKeyManagementKeys ()[0]);

            cdre.addLookupDescriptor (serverCryptoInterface.enumerateKeyManagementKeys ()[2])
                          .setEmail ("john.doe@example.com");

            cdre.addLookupDescriptor (serverCryptoInterface.enumerateKeyManagementKeys ()[2])
                          .setEmail ("jane.doe@example.com");

            cdre.addLookupDescriptor (serverCryptoInterface.enumerateKeyManagementKeys ()[1])
                          .setEmail ("john.doe@example.com")
                          .setPolicyRules (new String[]{"5.4.8","-5.4.9"})
                          .setSerialNumber (new BigInteger ("123"))
                          .setIssuedBefore (new Date (new Date ().getTime () - 100000))
                          .setIssuedAfter (new Date ())
                          .setSubject (new X500Principal ("CN=John"))
                          .setIssuer (new X500Principal ("CN=Root CA"));
            return cdre.writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create a key creation request for the client
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] keyCreRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            XMLObjectWrapper xml_object = server_xml_cache.parse (xmldata);
            if (xml_object instanceof ProvisioningInitializationResponseDecoder)
              {
                getProvSess (xml_object);
              }
            else
              {
                CredentialDiscoveryResponseDecoder cdrd = (CredentialDiscoveryResponseDecoder) xml_object;
                serverState.update (cdrd);
                CredentialDiscoveryResponseDecoder.LookupResult[] lres = cdrd.getLookupResults ();
// TODO verify
              }

            ServerState.PINPolicy pinPolicy = null;

            ServerState.PUKPolicy pukPolicy = null;
            
            if (puk_protection)
              {
                pukPolicy =
                    serverState.createPUKPolicy (new byte[]{'0','1','2','3','4','5','6', '7','8','9'},
                                                  PassphraseFormat.NUMERIC,
                                                  3);
              }
            if (pin_protection)
              {
                pinPolicy = serverState.createPINPolicy (PassphraseFormat.NUMERIC,
                                                           4,
                                                           8,
                                                           pin_retry_limit,
                                                           pukPolicy);
                if (add_pin_pattern)
                  {
                    pinPolicy.addPatternRestriction (PatternRestriction.THREE_IN_A_ROW);
                    pinPolicy.addPatternRestriction (PatternRestriction.SEQUENCE);
                  }
                if (pin_group_shared)
                  {
                    pinPolicy.setGrouping (Grouping.SHARED);
                  }
                if (inputMethod != null)
                  {
                    pinPolicy.setInputMethod (inputMethod);
                  }
                if (fixed_pin)
                  {
                    pinPolicy.setUserModifiable (false);
                  }
              }
            KeySpecifier key_alg = null;
            if (ecc_key)
              {
                key_alg = new KeySpecifier (KeyAlgorithms.NIST_P_256);
              }
            else if (ask_for_exponent)
              {
                key_alg = new KeySpecifier (KeyAlgorithms.RSA2048_EXP, 3);
              }
            else
              {
                key_alg = new KeySpecifier (ask_for_4096 ? KeyAlgorithms.RSA4096 : KeyAlgorithms.RSA2048);
              }

            ServerState.Key kp = devicePinProtection ?
                serverState.createDevicePINProtectedKey (AppUsage.AUTHENTICATION, key_alg) :
                  presetPin ? serverState.createKeyWithPresetPIN (encryption_key ? AppUsage.ENCRYPTION : AppUsage.AUTHENTICATION,
                                                                               key_alg, pinPolicy,
                                                                               PREDEF_SERVER_PIN)
                             :
            serverState.createKey (encryption_key || key_agreement? AppUsage.ENCRYPTION : AppUsage.AUTHENTICATION,
                                               key_alg,
                                               pinPolicy);
            if (symmetricKey || encryption_key)
              {
                kp.setEndorsedAlgorithms (new String[]{encryption_key ? SymEncryptionAlgorithms.AES256_CBC.getURI () : MACAlgorithms.HMAC_SHA1.getURI ()});
                kp.setSymmetricKey (encryption_key ? AES32BITKEY : OTP_SEED);
              }
            if (key_agreement)
              {
                kp.setEndorsedAlgorithms (new String[]{SecureKeyStore.ALGORITHM_ECDH_RAW});
              }
            if (propertyBag)
              {
                kp.addPropertyBag ("http://host/prop")
                  .addProperty ("main", "234", false)
                  .addProperty ("a", "fun", true);
              }
            if (encryptedExtension)
              {
                kp.addEncryptedExtension ("http://host/ee", new byte[]{0,5});
              }
            if (set_logotype)
              {
                kp.addLogotype (KeyGen2URIs.LOGOTYPES.CARD, new ImageData (new byte[]{8,6,4,4}, "image/png"));
              }
            if (exportProtection != null)
              {
                kp.setExportProtection (exportProtection);
              }
            if (deleteProtection != null)
              {
                kp.setDeleteProtection (deleteProtection);
              }
            if (enablePinCaching)
              {
                kp.setEnablePINCaching (true);
              }
            if (serverSeed)
              {
                byte[] seed = new byte[32];
                new SecureRandom ().nextBytes (seed);
                kp.setServerSeed (seed);
              }
            if (clone_key_protection != null)
              {
                kp.setClonedKeyProtection (clone_key_protection.serverState.getClientSessionId (), 
                                           clone_key_protection.serverState.getServerSessionId (),
                                           clone_key_protection.serverState.getKeys ()[0].getCertificatePath ()[0],
                                           clone_key_protection.server_km);
              }
            if (update_key != null)
              {
                kp.setUpdatedKey (update_key.serverState.getClientSessionId (), 
                                  update_key.serverState.getServerSessionId (),
                                  update_key.serverState.getKeys ()[0].getCertificatePath ()[0],
                                  update_kmk ? server_km : update_key.server_km);
              }
            if (delete_key != null)
              {
                serverState.addPostDeleteKey (delete_key.serverState.getClientSessionId (), 
                                               delete_key.serverState.getServerSessionId (),
                                               delete_key.serverState.getKeys ()[0].getCertificatePath ()[0],
                                               delete_key.server_km);
              }
            if (two_keys)
              {
                serverState.createKey (AppUsage.SIGNATURE, new KeySpecifier (KeyAlgorithms.NIST_P_256), pinPolicy);
              }

            return new KeyCreationRequestEncoder (serverState, KEY_INIT_URL).writeXML ();
          }


        ///////////////////////////////////////////////////////////////////////////////////
        // Get the key create response and respond with certified public keys and attributes
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] creFinalizeRequest (byte[] xmldata) throws IOException, GeneralSecurityException
          {
            if (plain_unlock_key == null)
              {
                boolean temp_set_private_key = set_private_key;
                boolean otp = symmetricKey && !encryption_key;
                KeyCreationResponseDecoder key_init_response = (KeyCreationResponseDecoder) server_xml_cache.parse (xmldata);
                serverState.update (key_init_response);
                for (ServerState.Key key_prop : serverState.getKeys ())
                  {
                    boolean auth = key_prop.getAppUsage () == AppUsage.AUTHENTICATION;
                    CertSpec cert_spec = new CertSpec ();
                    if (!otp)
                      {
                        // OTP certificates are just for transport
                        cert_spec.setEndEntityConstraint ();
                        if (auth)
                          {
                            cert_spec.setKeyUsageBit (KeyUsageBits.DIGITAL_SIGNATURE);
                            cert_spec.setKeyUsageBit (KeyUsageBits.KEY_AGREEMENT);
                          }
                        else
                          {
                            cert_spec.setKeyUsageBit (KeyUsageBits.DATA_ENCIPHERMENT);
                            cert_spec.setKeyUsageBit (KeyUsageBits.KEY_ENCIPHERMENT);
                          }
                      }
                    String extra = get_client_attributes ? ", SerialNumber=" + serverState.getClientAttributeValues ().get (KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER).iterator ().next () : "";
                    cert_spec.setSubject ("CN=KeyGen2 " + _name.getMethodName() + ", E=john.doe@example.com" +
                                          (otp ? ", OU=OTP Key" : extra));
                    otp = false;
    
                    GregorianCalendar start = new GregorianCalendar ();
                    GregorianCalendar end = (GregorianCalendar) start.clone ();
                    end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);
    
                    PublicKey pub_key =  key_prop.getPublicKey ();
    
                    if (temp_set_private_key)
                      {
                        KeyPairGenerator generator = KeyPairGenerator.getInstance (ecc_key ? "EC" :"RSA");
                        if (ecc_key)
                          {
                            generator.initialize (new ECGenParameterSpec ("P-256"), new SecureRandom ());
                          }
                        else
                          {
                            generator.initialize (new RSAKeyGenParameterSpec (1024, RSAKeyGenParameterSpec.F4), new SecureRandom ());
                          }
                        KeyPair kp = generator.generateKeyPair();
                        pub_key = kp.getPublic ();
                        gen_private_key = kp.getPrivate ();
                      }
    
                    Vector<X509Certificate> cert_path = new Vector<X509Certificate> ();
                    cert_path.add (new CA ().createCert (cert_spec,
                                                         DistinguishedName.subjectDN ((X509Certificate)DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")),
                                                         new BigInteger (String.valueOf (new Date ().getTime ())),
                                                         start.getTime (),
                                                         end.getTime (), 
                                                         AsymSignatureAlgorithms.RSA_SHA256,
                                                         new AsymKeySignerInterface ()
                        {
    
                          @Override
                          public PublicKey getPublicKey () throws IOException
                            {
                              try
                                {
                                  return ((X509Certificate)DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")).getPublicKey ();
                                }
                              catch (KeyStoreException e)
                                {
                                  throw new IOException (e);
                                }
                            }
    
                          @Override
                          public byte[] signData (byte[] data, AsymSignatureAlgorithms algorithm) throws IOException
                            {
                              try
                                {
                                  Signature signer = Signature.getInstance (algorithm.getJCEName ());
                                  signer.initSign ((PrivateKey) DemoKeyStore.getSubCAKeyStore ().getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
                                  signer.update (data);
                                  return signer.sign ();
                                }
                              catch (GeneralSecurityException e)
                                {
                                  throw new IOException (e);
                                }
                            }
                          
                        }, pub_key));

                    if (set_trust_anchor)
                      {
                        for (Certificate certificate : DemoKeyStore.getSubCAKeyStore ().getCertificateChain ("mykey"))
                          {
                            cert_path.add ((X509Certificate) certificate);
                          }
                        key_prop.setTrustAnchor (true);
                      }

                    key_prop.setCertificatePath (cert_path.toArray (new X509Certificate[0]));
    
                    if (temp_set_private_key)
                      {
                        key_prop.setPrivateKey (gen_private_key.getEncoded ());
                        temp_set_private_key = false;
                      }
    
                  }
              }
            else
              {
                CredentialDiscoveryResponseDecoder cdrd = (CredentialDiscoveryResponseDecoder) server_xml_cache.parse (xmldata);
                serverState.update (cdrd);
                CredentialDiscoveryResponseDecoder.LookupResult[] lres = cdrd.getLookupResults ();
// TODO verify
                serverState.addPostUnlockKey (plain_unlock_key.serverState.getClientSessionId (), 
                                               plain_unlock_key.serverState.getServerSessionId (),
                                               plain_unlock_key.serverState.getKeys ()[0].getCertificatePath ()[0],
                                               plain_unlock_key.server_km);
              }

            return new ProvisioningFinalizationRequestEncoder (serverState, FIN_PROV_URL).writeXML ();
          }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally we get the attestested response
        ///////////////////////////////////////////////////////////////////////////////////
        void creFinalizeResponse (byte[] xmldata) throws IOException
          {
            ProvisioningFinalizationResponseDecoder prov_final_response = (ProvisioningFinalizationResponseDecoder) server_xml_cache.parse (xmldata);
            serverState.update (prov_final_response);

            ///////////////////////////////////////////////////////////////////////////////////
            // Just a small consistency check
            ///////////////////////////////////////////////////////////////////////////////////
            ByteArrayOutputStream baos = new ByteArrayOutputStream ();
            new ObjectOutputStream (baos).writeObject (serverState);
            byte[] serialized = baos.toByteArray ();
            try
              {
                ServerState scs = (ServerState) new ObjectInputStream (new ByteArrayInputStream (serialized)).readObject ();
              }
            catch (ClassNotFoundException e)
              {
                throw new IOException (e);
              }
          }
      }
    
    class Doer
      {
        Server server;
        Client client;
        XMLSchemaCache xmlschemas = new XMLSchemaCache ();
        int pass;
        
        private void write (byte[] data) throws Exception
          {
            if (fos != null)
              {
                for (int i = 0; i < data.length; i++)
                  {
                    byte b = data[i];
                    if (b == '\n')
                      {
                        fos.write ("<br>".getBytes ("UTF-8"));
                      }
                    else
                      {
                        fos.write (b);
                      }
                  }
              }
          }
        
        private void write (int b) throws Exception
          {
            write (new byte[]{(byte)b}); 
          }
        
        private void writeString (String message) throws Exception
          {
            write (message.getBytes ("UTF-8"));
          }
        
        private void writeOption (String option, boolean writeit) throws Exception
          {
            if (writeit)
              {
                writeString (option);
                write ('\n');
              }
          }
        
        byte[] fileLogger (byte[] xmldata) throws Exception
          {
            XMLObjectWrapper xo = xmlschemas.parse (xmldata);
            writeString ("&nbsp;<br><table><tr><td bgcolor=\"#F0F0F0\" style=\"border:solid;border-width:1px;padding:4px\">&nbsp;Pass #" + 
                         (++pass) +
                         ":&nbsp;" + 
                         xo.element () +
                         "<a id=\"" +
                         xo.element () +
                         "." +
                         _name.getMethodName() +
                         "." +
                         round +
                         "\"/>&nbsp;</td></tr></table>&nbsp;<br>");
            writeString (XML2HTMLPrinter.convert (new String (xmldata, "UTF-8")));
            return xmldata;
          }

        
        Doer () throws Exception
          {
            xmlschemas.addWrapper (PlatformNegotiationRequestDecoder.class);
            xmlschemas.addWrapper (PlatformNegotiationResponseDecoder.class);
            xmlschemas.addWrapper (ProvisioningInitializationRequestDecoder.class);
            xmlschemas.addWrapper (ProvisioningInitializationResponseDecoder.class);
            xmlschemas.addWrapper (CredentialDiscoveryRequestDecoder.class);
            xmlschemas.addWrapper (CredentialDiscoveryResponseDecoder.class);
            xmlschemas.addWrapper (KeyCreationRequestDecoder.class);
            xmlschemas.addWrapper (KeyCreationResponseDecoder.class);
            xmlschemas.addWrapper (ProvisioningFinalizationRequestDecoder.class);
            xmlschemas.addWrapper (ProvisioningFinalizationResponseDecoder.class);
          }
        
        void perform () throws Exception
          {
            writeString ("<b>");
            writeString ("Begin Test (" + _name.getMethodName() + ":" + (++round) + ")</b><br>");
            writeOption ("4096 over 2048 RSA key preference", ask_for_4096);
            writeOption ("RSA key with custom exponent", ask_for_exponent);
            writeOption ("Get client attributes", get_client_attributes);
            writeOption ("Client shows one image preference", image_prefs);
            writeOption ("PUK Protection", puk_protection);
            writeOption ("PIN Protection ", pin_protection);
            writeOption ("PIN Input Method ", inputMethod != null);
            writeOption ("Device PIN", devicePinProtection);
            writeOption ("Preset PIN", presetPin);
            writeOption ("Enable PIN Caching", enablePinCaching);
            writeOption ("PIN patterns", add_pin_pattern);
            writeOption ("Fixed PIN", fixed_pin);
            writeOption ("Privacy Enabled", privacy_enabled);
            writeOption ("ECC Key", ecc_key);
            writeOption ("Server Seed", serverSeed);
            writeOption ("PropertyBag", propertyBag);
            writeOption ("Symmetric Key", symmetricKey);
            writeOption ("Encryption Key", encryption_key);
            writeOption ("Encrypted Extension", encryptedExtension);
            writeOption ("Delete Protection", deleteProtection != null);
            writeOption ("Export Protection", exportProtection != null);
            writeOption ("Private Key Import", set_private_key);
            writeOption ("Logotype Option", set_logotype);
            writeOption ("Updatable Session", updatable);
            writeOption ("CloneKeyProtection", clone_key_protection != null);
            writeOption ("UpdateKey", update_key != null);
            writeOption ("DeleteKey", delete_key != null);
            writeOption ("UnlockKey", plain_unlock_key != null);
            writeOption ("ECC KMK", ecc_kmk);
            writeOption ("Update KMK", update_kmk);
            writeOption ("Multiple Keys", two_keys);
            writeOption ("HTTPS server certificate", https);
            writeOption ("TrustAnchor option", set_trust_anchor);
            writeOption ("Abort URL option", set_abort_url);
            writeOption ("Virtual Machine option", virtual_machine);
            server = new Server ();
            client = new Client ();
            byte[] xml;
            xml = fileLogger (server.platformRequest ());
            xml = fileLogger (client.platformResponse (xml));
            xml = fileLogger (server.provSessRequest (xml));
            xml = fileLogger (client.provSessResponse (xml));
            if (delete_key != null || clone_key_protection != null || update_key != null || plain_unlock_key != null)
              {
                xml = fileLogger (server.creDiscRequest (xml));
                xml = fileLogger (client.creDiscResponse (xml));
              }
            if (plain_unlock_key == null)
              {
                xml = fileLogger (server.keyCreRequest (xml));
                xml = fileLogger (client.keyCreResponse (xml));
              }
            xml = fileLogger (server.creFinalizeRequest (xml));
            xml = fileLogger (client.creFinalizeResponse (xml));
            server.creFinalizeResponse (xml);
            writeString ("\n");
            EnumeratedKey ek = new EnumeratedKey ();
            while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
              {
                if (ek.getProvisioningHandle () == client.provisioning_handle)
                  {
                    KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                    writeString ("Deployed key[" + ek.getKeyHandle () + "] " + CertificateUtil.convertRFC2253ToLegacy (ka.getCertificatePath ()[0].getSubjectX500Principal ().getName ()) + "\n");
                  }
              }
            writeString ("\n\n");
         }
        
        int getFirstKey () throws Exception
          {
            EnumeratedKey ek = new EnumeratedKey ();
            while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
              {
                if (ek.getProvisioningHandle () == client.provisioning_handle)
                  {
                    break;
                  }
              }
            assertTrue ("Missing keys", ek != null);
            return ek.getKeyHandle ();
          }

        
      }

    @Test
    public void StrongRSAPreferences () throws Exception
      {
        ask_for_4096 = true;
        new Doer ().perform ();
      }

    @Test
    public void RSAExponentPreferences () throws Exception
      {
        ask_for_exponent = true;
        new Doer ().perform ();
      }

    @Test
    public void BrainpoolOption () throws Exception
      {
        brain_pool = true;
        new Doer ().perform ();
      }

    @Test
    public void ClientAttributes () throws Exception
      {
        get_client_attributes = true;
        new Doer ().perform ();
      }

    @Test
    public void ImagePreferences () throws Exception
      {
        Doer doer = new Doer ();
        image_prefs = true;
        pin_protection = true;
        doer.perform ();
      }

    @Test
    public void PINPatterns () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        add_pin_pattern = true;
        ecc_key = true;
        https = true;
        doer.perform ();
      }

    @Test
    public void ServerCertificate () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        ecc_key = true;
        https = true;
        doer.perform ();
      }

    @Test
    public void ServerSeed () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        fixed_pin = true;
        serverSeed = true;
        doer.perform ();
        assertFalse ("PIN Not User Modifiable", sks.getKeyProtectionInfo (doer.getFirstKey ()).getPINUserModifiableFlag ());
      }

    @Test
    public void MultipleKeys () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        two_keys = true;
        doer.perform ();
      }

    @Test
    public void EncryptedExtension () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        ecc_key = true;
        propertyBag = true;
        encryptedExtension = true;
        serverSeed = true;
        doer.perform ();
      }

    @Test
    public void InputMethod () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        puk_protection = true;
        inputMethod = InputMethod.PROGRAMMATIC;
        doer.perform ();
      }

    @Test
    public void PropertyBag () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        symmetricKey = true;
        propertyBag = true;
        doer.perform ();
        int keyHandle = doer.getFirstKey ();
        ServerState.PropertyBag prop_bag = doer.server.serverState.getKeys ()[0].getPropertyBags ()[0];
        Property[] props1 = sks.getExtension (keyHandle, prop_bag.getType ()).getProperties ();
        ServerState.Property[] props2 = prop_bag.getProperties ();
        assertTrue ("Prop len error", props1.length == props2.length);
        int w = 0;
        for (int i = 0; i < props1.length; i++)
          {
            if (props2[i].isWritable ())
              {
                w = i;
              }
            assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
            assertTrue ("Prop value error", props1[i].getValue ().equals (props2[i].getValue ()));
          }
        sks.setProperty (keyHandle, prop_bag.getType (), props2[w].getName (), props2[w].getValue () + "w2");
        props1 = sks.getExtension (keyHandle, prop_bag.getType ()).getProperties ();
        for (int i = 0; i < props1.length; i++)
          {
            assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
            assertTrue ("Prop value error", (i == w) ^ props1[i].getValue ().equals (props2[i].getValue ()));
          }
        sks.setProperty (keyHandle, prop_bag.getType (), props2[w].getName (), props2[w].getValue ());
        props1 = sks.getExtension (keyHandle, prop_bag.getType ()).getProperties ();
        for (int i = 0; i < props1.length; i++)
          {
            assertTrue ("Prop name error", props1[i].getName ().equals (props2[i].getName ()));
            assertTrue ("Prop value error", props1[i].getValue ().equals (props2[i].getValue ()));
          }
        assertTrue ("HMAC error", ArrayUtil.compare (sks.performHMAC (keyHandle,
                                                                      MACAlgorithms.HMAC_SHA1.getURI (),
                                                                      null,
                                                                      USER_DEFINED_PIN, TEST_STRING),
                                                     MACAlgorithms.HMAC_SHA1.digest (OTP_SEED, TEST_STRING)));
      }

    @Test
    public void Logotype () throws Exception
      {
        Doer doer = new Doer ();
        set_logotype = true;
        doer.perform ();
      }

   @Test
    public void ImportSymmetricKey () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        encryption_key = true;
        symmetricKey = true;
        doer.perform ();
        int keyHandle = doer.getFirstKey ();
        byte[] iv = null;
        byte[] enc = sks.symmetricKeyEncrypt (keyHandle,
                                              SymEncryptionAlgorithms.AES256_CBC.getURI (),
                                              true,
                                              iv,
                                              USER_DEFINED_PIN,
                                              TEST_STRING);
        assertTrue ("Encrypt/decrypt error", ArrayUtil.compare (sks.symmetricKeyEncrypt (keyHandle,
                                                                                         SymEncryptionAlgorithms.AES256_CBC.getURI (),
                                                                                         false,
                                                                                         iv,
                                                                                         USER_DEFINED_PIN, 
                                                                                         enc),
                                                                                         TEST_STRING));
        assertFalse ("PIN Cached", sks.getKeyProtectionInfo (keyHandle).getEnablePINCachingFlag ());
      }

    @Test
    public void DevicePIN () throws Exception
      {
        Doer doer = new Doer ();
        devicePinProtection = true;
        set_abort_url = true;
        doer.perform ();
      }

    @Test
    public void PresetPIN () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        presetPin = true;
        enablePinCaching = true;
        inputMethod = InputMethod.TRUSTED_GUI;
        doer.perform ();
        assertTrue ("PIN User Modifiable", sks.getKeyProtectionInfo (doer.getFirstKey ()).getPINUserModifiableFlag ());
        assertTrue ("PIN Not Cached", sks.getKeyProtectionInfo (doer.getFirstKey ()).getEnablePINCachingFlag ());
      }

    @Test
    public void CloneKeyProtection () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        ecc_kmk = true;
        pin_protection = true;
        pin_group_shared = true;
        doer1.perform ();
        updatable = false;
        pin_protection = false;
        clone_key_protection = doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer2.client.provisioning_handle)
              {
                j++;
                KeyAttributes ka = sks.getKeyAttributes (ek.getKeyHandle ());
                byte[] result = sks.signHashedData (ek.getKeyHandle (),
                                                    AsymSignatureAlgorithms.RSA_SHA256.getURI (),
                                                    null,
                                                    USER_DEFINED_PIN,
                                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                Signature verify = Signature.getInstance (AsymSignatureAlgorithms.RSA_SHA256.getJCEName ());
                verify.initVerify (ka.getCertificatePath ()[0]);
                verify.update (TEST_STRING);
                assertTrue ("Bad signature", verify.verify (result));
              }
          }
        assertTrue ("Missing keys", j == 2);
      }

    @Test
    public void UpdateKey () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        pin_protection = true;
        pin_group_shared = true;
        doer1.perform ();
        updatable = false;
        pin_protection = false;
        update_key= doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        int keyHandle = doer2.getFirstKey ();
        KeyAttributes ka = sks.getKeyAttributes (keyHandle);
        byte[] result = sks.signHashedData (keyHandle,
                                            AsymSignatureAlgorithms.RSA_SHA256.getURI (),
                                            null,
                                            USER_DEFINED_PIN,
                                            HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature verify = Signature.getInstance (AsymSignatureAlgorithms.RSA_SHA256.getJCEName ());
        verify.initVerify (ka.getCertificatePath ()[0]);
        verify.update (TEST_STRING);
        assertTrue ("Bad signature", verify.verify (result));
      }

    @Test
    public void UpdateKeyManagementKey () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        pin_protection = true;
        pin_group_shared = true;
        doer1.perform ();
        updatable = true;
        pin_protection = false;
        update_kmk = true;
        update_key= doer1.server;
        ecc_kmk = true;
        Doer doer2 = new Doer ();
        doer2.perform ();
        int keyHandle = doer2.getFirstKey ();
        KeyAttributes ka = sks.getKeyAttributes (keyHandle);
        byte[] result = sks.signHashedData (keyHandle,
                                            AsymSignatureAlgorithms.RSA_SHA256.getURI (),
                                            null,
                                            USER_DEFINED_PIN,
                                            HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature verify = Signature.getInstance (AsymSignatureAlgorithms.RSA_SHA256.getJCEName ());
        verify.initVerify (ka.getCertificatePath ()[0]);
        verify.update (TEST_STRING);
        assertTrue ("Bad signature", verify.verify (result));
      }

    @Test
    public void DeleteKey () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        doer1.perform ();
        updatable = false;
        delete_key= doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        EnumeratedKey ek = new EnumeratedKey ();
        int j = 0;
        while ((ek = sks.enumerateKeys (ek.getKeyHandle ())) != null)
          {
            if (ek.getProvisioningHandle () == doer1.client.provisioning_handle)
              {
                j++;
              }
          }
        assertTrue ("Too many keys", j == 0);
      }

    @Test
    public void ImportPrivateKey () throws Exception
      {
        Doer doer = new Doer ();
        set_private_key = true;
        pin_protection = true;
        doer.perform ();
        int keyHandle = doer.getFirstKey ();
        byte[] result = sks.signHashedData (keyHandle,
                                            AsymSignatureAlgorithms.RSA_SHA256.getURI (),
                                            null,
                                            USER_DEFINED_PIN,
                                            HashAlgorithms.SHA256.digest (TEST_STRING));
        Signature sign = Signature.getInstance (AsymSignatureAlgorithms.RSA_SHA256.getJCEName ());
        sign.initSign (doer.server.gen_private_key);
        sign.update (TEST_STRING);
        assertTrue ("Bad signature", ArrayUtil.compare (sign.sign (), result));
      }

    @Test
    public void ExportProtection () throws Exception
      {
        for (ExportProtection exp_pol : ExportProtection.values ())
          {
            Doer doer = new Doer ();
            exportProtection = exp_pol;
            pin_protection = exp_pol == ExportProtection.PIN || exp_pol == ExportProtection.PUK;
            puk_protection = exp_pol == ExportProtection.PUK;
            ecc_key = true;
            doer.perform ();
            KeyProtectionInfo kpi = sks.getKeyProtectionInfo (doer.getFirstKey ());
            assertTrue ("Export prot", kpi.getExportProtection () == exp_pol);
          }
      }

    @Test
    public void DeleteProtection () throws Exception
      {
        for (DeleteProtection del_pol : DeleteProtection.values ())
          {
            Doer doer = new Doer ();
            pin_protection = del_pol == DeleteProtection.PIN || del_pol == DeleteProtection.PUK;
            puk_protection = del_pol == DeleteProtection.PUK;
            deleteProtection = del_pol;
            ecc_key = true;
            doer.perform ();
            KeyProtectionInfo kpi = sks.getKeyProtectionInfo (doer.getFirstKey ());
            assertTrue ("Delete prot", kpi.getDeleteProtection () == del_pol);
          }
      }

    @Test
    public void KeyAgreement () throws Exception
      {
        Doer doer = new Doer ();
        pin_protection = true;
        ecc_key = true;
        key_agreement = true;
        doer.perform ();
        int keyHandle = doer.getFirstKey ();
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("secp256r1");
        generator.initialize (eccgen, new SecureRandom ());
        KeyPair kp = generator.generateKeyPair ();
        KeyAttributes ka = sks.getKeyAttributes (keyHandle);
        byte[] z = sks.keyAgreement (keyHandle,
                                     SecureKeyStore.ALGORITHM_ECDH_RAW,
                                     null,
                                     USER_DEFINED_PIN, 
                                     (ECPublicKey)kp.getPublic ());
        KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
        key_agreement.init (kp.getPrivate ());
        key_agreement.doPhase (ka.getCertificatePath ()[0].getPublicKey (), true);
        byte[] Z = key_agreement.generateSecret ();
        assertTrue ("DH fail", ArrayUtil.compare (z, Z));
      }

    @Test
    public void UnlockKey () throws Exception
      {
        Doer doer1 = new Doer ();
        updatable = true;
        pin_protection = true;
        ecc_key = true;
        doer1.perform ();
        int keyHandle = doer1.getFirstKey ();
        for (int i = 1; i <= doer1.server.pin_retry_limit; i++)
          {
            try
              {
                sks.signHashedData (keyHandle,
                                    AsymSignatureAlgorithms.ECDSA_SHA256.getURI (),
                                    null,
                                    BAD_PIN,
                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                fail ("Bad PIN should not work");
              }
            catch (SKSException e)
              {
                assertFalse ("Locked", sks.getKeyProtectionInfo (keyHandle).isPINBlocked () ^ (i == doer1.server.pin_retry_limit));
              }
          }

        updatable = false;
        pin_protection = false;
        ecc_key = false;
        plain_unlock_key = doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        assertFalse ("UnLocked", sks.getKeyProtectionInfo (keyHandle).isPINBlocked ());
      }

    @Test
    public void PrivacyEnabled () throws Exception
      {
        Doer doer1 = new Doer ();
        privacy_enabled = true;
        updatable = true;
        pin_protection = true;
        ecc_key = true;
        doer1.perform ();
        int keyHandle = doer1.getFirstKey ();
        for (int i = 1; i <= doer1.server.pin_retry_limit; i++)
          {
            try
              {
                sks.signHashedData (keyHandle,
                                    AsymSignatureAlgorithms.ECDSA_SHA256.getURI (),
                                    null,
                                    BAD_PIN,
                                    HashAlgorithms.SHA256.digest (TEST_STRING));
                fail ("Bad PIN should not work");
              }
            catch (SKSException e)
              {
                assertFalse ("Locked", sks.getKeyProtectionInfo (keyHandle).isPINBlocked () ^ (i == doer1.server.pin_retry_limit));
              }
          }

        updatable = false;
        pin_protection = false;
        ecc_key = false;
        plain_unlock_key= doer1.server;
        Doer doer2 = new Doer ();
        doer2.perform ();
        assertFalse ("UnLocked", sks.getKeyProtectionInfo (keyHandle).isPINBlocked ());
        assertTrue ("PIN User Modifiable", sks.getKeyProtectionInfo (keyHandle).getPINUserModifiableFlag ());
      }

    @Test
    public void TrustAnchor () throws Exception
      {
        Doer doer = new Doer ();
        set_trust_anchor = true;
        doer.perform ();
        X509Certificate[] cert_path = sks.getKeyAttributes (doer.getFirstKey ()).getCertificatePath ();
        assertTrue ("Path Length", CertificateUtil.isTrustAnchor (cert_path[cert_path.length - 1]));
      }

    @Test
    public void VirtualMachine () throws Exception
      {
        Doer doer = new Doer ();
        virtual_machine = true;
        doer.perform ();
      }

    @Test
    public void MassiveUserPINCollection () throws Exception
      {
        assertTrue (PINCheck (PassphraseFormat.ALPHANUMERIC, null, "AB123"));
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, null, "1234"));
        assertTrue (PINCheck (PassphraseFormat.STRING, null, "azAB13.\n"));
        assertTrue (PINCheck (PassphraseFormat.BINARY, null, "12300234FF"));
        assertTrue (PINCheck (PassphraseFormat.BINARY, null, "12300234ff"));
        assertFalse (PINCheck (PassphraseFormat.BINARY, null, "3034ff"));
        assertFalse (PINCheck (PassphraseFormat.BINARY, null, "12300234fp"));

        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, null, "ab123"));  // Lowercase 
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, null, "AB1234"));      // Alpha

        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1234"));      // Up seq
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "8765"));      // Down seq
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1235"));      // No seq
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1345"));      // No seq

        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "1232"));      // No two in row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "11345"));      // Two in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "13455"));      // Two in a row

        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "11232"));      // No two in row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "111345"));      // Three in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "134555"));      // Three in a row
        
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "1235"));      // No seq or three in a row
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "6789"));      // Seq
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "1115"));      // Three in a row

        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "1476"));      // Bad combo
        assertFalse (PINCheck (PassphraseFormat.BINARY, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "12300234FF"));      // Bad combo

        assertTrue (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2aZ."));
        assertTrue (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "AB34"));

        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2aZA"));  // Non alphanum missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "a.jZ"));  // Number missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2 ZA"));  // Lowercase missing
        assertFalse (PINCheck (PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2a 6"));  // Uppercase missing

        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "ABCK")); // Missing number
        assertFalse (PINCheck (PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "1235")); // Missing alpha
        
        assertTrue (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.REPEATED}, "1345"));
        assertFalse (PINCheck (PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.REPEATED}, "1315"));  // Two of same

        PINGroupCheck (Grouping.NONE, new AppUsage[] {AppUsage.AUTHENTICATION}, new String[] {"1234"}, new int[] {0}, false);
        PINGroupCheck (Grouping.NONE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234", "1234"}, new int[] {0, 1}, false);
        PINGroupCheck (Grouping.NONE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234", "1235"}, new int[] {0, 1}, false);
        PINGroupCheck (Grouping.SHARED, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234", "1234"}, new int[] {0, 1}, true);
        PINGroupCheck (Grouping.SHARED, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE, AppUsage.SIGNATURE}, new String[] {"1234"}, new int[] {0, 0, 0}, false);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234"}, new int[] {0, 0}, true);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234","2345"}, new int[] {0, 1}, false);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234","1234"}, new int[] {0, 1}, true);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.SIGNATURE, AppUsage.AUTHENTICATION, AppUsage.SIGNATURE}, new String[] {"1234","2345"}, new int[] {0, 1, 0}, false);
        PINGroupCheck (Grouping.UNIQUE, new AppUsage[] {AppUsage.SIGNATURE, AppUsage.AUTHENTICATION, AppUsage.SIGNATURE, AppUsage.ENCRYPTION}, new String[] {"1234","2345","7777"}, new int[] {0, 1, 0, 2}, false);
        PINGroupCheck (Grouping.SIGNATURE_PLUS_STANDARD, new AppUsage[] {AppUsage.SIGNATURE, AppUsage.AUTHENTICATION, AppUsage.SIGNATURE, AppUsage.ENCRYPTION}, new String[] {"2345","1234"}, new int[] {0, 1, 0, 1}, false);
        PINGroupCheck (Grouping.SIGNATURE_PLUS_STANDARD, new AppUsage[] {AppUsage.SIGNATURE, AppUsage.AUTHENTICATION, AppUsage.SIGNATURE, AppUsage.ENCRYPTION}, new String[] {"2345","2345"}, new int[] {0, 1, 0, 1}, true);
      }
  }
