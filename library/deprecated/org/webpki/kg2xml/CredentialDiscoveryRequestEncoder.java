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

import java.math.BigInteger;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;

import java.util.Date;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;

import org.webpki.xmldsig.XMLAsymKeySigner;
import org.webpki.xmldsig.XMLEnvelopedInput;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignerInterface;

import org.webpki.kg2xml.ServerState.ProtocolPhase;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class CredentialDiscoveryRequestEncoder extends CredentialDiscoveryRequest
  {
    ServerCryptoInterface serverCryptoInterface;

    public class LookupDescriptor extends XMLObjectWrapper implements XMLEnvelopedInput, AsymKeySignerInterface
      {
        PublicKey keyManagementKey;

        String id;
        
        boolean searchFilter;

        String issuer_reg_ex;
        String subject_reg_ex;
        BigInteger serialNumber;
        String email_reg_ex;
        String[] policy_rules;
        Date issuedBefore;
        Date issuedAfter;
        
        Document root;
        

        LookupDescriptor (PublicKey keyManagementKey)
          {
            this.keyManagementKey = keyManagementKey;
            this.id = lookupPrefix + ++nextLookupIdSuffix;
          }
        
        private void nullCheck (Object object) throws IOException
          {
            if (object == null)
              {
                throw new IOException ("Null search parameter not allowed");
              }
          }

        public LookupDescriptor setSubjectRegEx (String subject_reg_ex) throws IOException
          {
            nullCheck (subject_reg_ex);
            searchFilter = true;
            this.subject_reg_ex = subject_reg_ex;
            return this;
          }

        public LookupDescriptor setSubject (X500Principal subject) throws IOException
          {
            nullCheck (subject);
            return setSubjectRegEx (new CertificateFilter ().setSubject (subject).getSubjectRegEx ());
          }

        public LookupDescriptor setIssuerRegEx (String issuer_reg_ex) throws IOException
          {
            nullCheck (issuer_reg_ex);
            searchFilter = true;
            this.issuer_reg_ex = issuer_reg_ex;
            return this;
          }
  
        public LookupDescriptor setIssuer (X500Principal issuer) throws IOException
          {
            nullCheck (issuer);
            return setIssuerRegEx (new CertificateFilter ().setIssuer (issuer).getIssuerRegEx ());
          }
  
        public LookupDescriptor setSerialNumber (BigInteger serialNumber) throws IOException
          {
            nullCheck (serialNumber);
            searchFilter = true;
            this.serialNumber = serialNumber;
            return this;
          }
  
        public LookupDescriptor setEmailRegEx (String email_reg_ex) throws IOException
          {
            nullCheck (email_reg_ex);
            searchFilter = true;
            this.email_reg_ex = email_reg_ex;
            return this;
          }
  
        public LookupDescriptor setEmail (String email) throws IOException
          {
            nullCheck (email);
            return setEmailRegEx (new CertificateFilter ().setEmail (email).getEmailRegEx ());
          }
  
        public LookupDescriptor setPolicyRules (String[] policy_rules) throws IOException
          {
            nullCheck (policy_rules);
            searchFilter = true;
            this.policy_rules = new CertificateFilter ().setPolicyRules (policy_rules).getPolicyRules ();
            return this;
          }
  
        public LookupDescriptor setIssuedBefore (Date issuedBefore) throws IOException
          {
            nullCheck (issuedBefore);
            searchFilter = true;
            this.issuedBefore = issuedBefore;
            return this;
          }
  
        public LookupDescriptor setIssuedAfter (Date issuedAfter) throws IOException
          {
            nullCheck (issuedAfter);
            searchFilter = true;
            this.issuedAfter = issuedAfter;
            return this;
          }


        @Override
        public String element ()
          {
            return LOOKUP_SPECIFIER_ELEM;
          }

        @Override
        protected void fromXML (DOMReaderHelper rd) throws IOException
          {
            throw new IOException ("Should not be called");
          }

        @Override
        protected boolean hasQualifiedElements ()
          {
            return true;
          }

        @Override
        protected void init () throws IOException
          {
          }

        @Override
        public String namespace ()
          {
            return KEYGEN2_NS;
          }

        @Override
        protected void toXML (DOMWriterHelper wr) throws IOException
          {
            wr.initializeRootObject (prefix);

            wr.setBinaryAttribute (NONCE_ATTR, nonce);
            
            wr.setStringAttribute (ID_ATTR, id);
            if (searchFilter)
              {
                wr.addChildElement (SEARCH_FILTER_ELEM);
                if (subject_reg_ex != null)
                  {
                    wr.setStringAttribute (CertificateFilter.CF_SUBJECT_REG_EX, subject_reg_ex);
                  }
                if (issuer_reg_ex != null)
                  {
                    wr.setStringAttribute (CertificateFilter.CF_ISSUER_REG_EX, issuer_reg_ex);
                  }
                if (serialNumber != null)
                  {
                    wr.setBigIntegerAttribute (CertificateFilter.CF_SERIAL_NUMBER, serialNumber);
                  }
                if (email_reg_ex != null)
                  {
                    wr.setStringAttribute (CertificateFilter.CF_EMAIL_REG_EX, email_reg_ex);
                  }
                if (policy_rules != null)
                  {
                    wr.setListAttribute (CertificateFilter.CF_POLICY_RULES, policy_rules);
                  }
                if (issuedBefore != null)
                  {
                    wr.setDateTimeAttribute (ISSUED_BEFORE_ATTR, issuedBefore);
                  }
                if (issuedAfter != null)
                  {
                    wr.setDateTimeAttribute (ISSUED_AFTER_ATTR, issuedAfter);
                  }
                wr.getParent ();
              }
          }

        @Override
        public Document getEnvelopeRoot () throws IOException
          {
            return root = getRootDocument ();
          }

        @Override
        public Element getInsertElem () throws IOException
          {
            return null;
          }

        @Override
        public String getReferenceURI () throws IOException
          {
            return id;
          }

        @Override
        public XMLSignatureWrapper getSignature () throws IOException
          {
            throw new IOException ("Should not be called");
          }

        @Override
        public Element getTargetElem () throws IOException
          {
            return null;
          }

        @Override
        public PublicKey getPublicKey () throws IOException
          {
            return keyManagementKey;
          }

        @Override
        public byte[] signData (byte[] data, AsymSignatureAlgorithms algorithm) throws IOException
          {
            return serverCryptoInterface.generateKeyManagementAuthorization (keyManagementKey, data);
          }
      }

 
    private String prefix;  // Default: no prefix
    
    Vector<LookupDescriptor> lookup_descriptors = new Vector<LookupDescriptor> ();

    String lookupPrefix = "Lookup.";
    
    byte[] nonce;
    
    int nextLookupIdSuffix = 0;
    
    boolean ecc_keys;

    // Constructors

    public CredentialDiscoveryRequestEncoder (ServerState serverState, String submitUrl) throws IOException
      {
        serverState.checkState (true, ProtocolPhase.CREDENTIAL_DISCOVERY);
        clientSessionId = serverState.clientSessionId;
        serverSessionId = serverState.serverSessionId;
        serverCryptoInterface = serverState.serverCryptoInterface;
        super.submitUrl = submitUrl;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, serverSessionId);
      }

    
    public LookupDescriptor addLookupDescriptor (PublicKey keyManagementKey)
      {
        LookupDescriptor lo_des = new LookupDescriptor (keyManagementKey);
        lookup_descriptors.add (lo_des);
        if (keyManagementKey instanceof ECPublicKey)
          {
            ecc_keys = true;
          }
        return lo_des;
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ID_ATTR, serverSessionId);

        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, clientSessionId);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submitUrl);
        
        XMLSignatureWrapper.addXMLSignatureNS (wr);
        
        if (ecc_keys)
          {
            XMLSignatureWrapper.addXMLSignature11NS (wr);
          }

        ////////////////////////////////////////////////////////////////////////
        // Lookup descriptors
        ////////////////////////////////////////////////////////////////////////
        if (lookup_descriptors.isEmpty ())
          {
            throw new IOException ("There must be at least one descriptor defined");
          }
        MacGenerator concat = new MacGenerator ();
        concat.addString (clientSessionId);
        concat.addString (serverSessionId);
        nonce = HashAlgorithms.SHA256.digest (concat.getResult ());
        for (LookupDescriptor im_des : lookup_descriptors)
          {
            XMLAsymKeySigner ds = new XMLAsymKeySigner (im_des);
            ds.setSignatureAlgorithm (im_des.keyManagementKey instanceof ECPublicKey ? AsymSignatureAlgorithms.ECDSA_SHA256 : AsymSignatureAlgorithms.RSA_SHA256);
            ds.removeXMLSignatureNS ();
            ds.createEnvelopedSignature (im_des);
            im_des.root.getDocumentElement ().removeAttributeNS ("http://www.w3.org/2000/xmlns/", prefix == null ? "xmlns" : prefix);
            wr.addWrapped (im_des);
          }
      }
  }
