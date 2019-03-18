/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
namespace org.webpki.sks.ws.client
{
    using org.webpki.sks.ws.client.BouncyCastle.Asn1;

    using org.webpki.sks.ws.client.BouncyCastle.Utilities.Encoders;
    
    using System;
    
    using System.Collections.Generic; 
    
    public static class Conversions
    {
        public const string EC_PUBLIC_KEY  = "1.2.840.10045.2.1";
        
        public const string RSA_PUBLIC_KEY = "1.2.840.113549.1.1.1";
        
        internal static void TestKey (string oid, bool ec_flag)
        {
            if (oid == RSA_PUBLIC_KEY)
            {
                if (ec_flag)
                {
                    throw new System.ArgumentException ("EC key expected");
                }
            }
            else if (oid != EC_PUBLIC_KEY)
            {
                throw new System.ArgumentException ("Unknown key type: " + oid);
            }
        }
        
        // Extension method to the .NET PublicKey class
        public static string Format(this System.Security.Cryptography.X509Certificates.PublicKey public_key)
        {
            Asn1Sequence inner = Asn1Sequence.GetInstance(Asn1Object.FromByteArray (EncodeX509PublicKey (public_key)));
            byte[] raw_key = DerBitString.GetInstance (inner[1]).GetBytes ();
            Asn1Sequence algorithm = Asn1Sequence.GetInstance (inner[0]);
            if (DerObjectIdentifier.GetInstance(algorithm[0]).Id == RSA_PUBLIC_KEY)
            {
               Asn1Sequence rsa_values = Asn1Sequence.GetInstance(Asn1Object.FromByteArray (raw_key));
               return "RSA Public Key (" + Hex.ToHexString (DerInteger.GetInstance (rsa_values[0]).Value.ToByteArrayUnsigned ()) + ", " +
                      DerInteger.GetInstance (rsa_values[1]).ToString () + ")";
            }
            else
            {
               return "EC Public Key (" + DerObjectIdentifier.GetInstance(algorithm[1]).Id + ", " + Hex.ToHexString (raw_key) + ")";
            }
        }

        // Extension method to the .NET PublicKey class
        public static byte[] X509Encoding(this System.Security.Cryptography.X509Certificates.PublicKey public_key)
        {
            return EncodeX509PublicKey (public_key);
        }

        // Extension method to the .NET PublicKey class
        public static bool IsRSA(this System.Security.Cryptography.X509Certificates.PublicKey public_key)
        {
            return public_key.Oid.Value == Conversions.RSA_PUBLIC_KEY;
        }

        internal static byte[] EncodeX509PublicKey (System.Security.Cryptography.X509Certificates.PublicKey public_key, bool ec_flag)
        {
            if (public_key == null)
            {
                return null;
            }
            TestKey (public_key.Oid.Value, ec_flag);
            DerSequence algorithm = new DerSequence (new DerObjectIdentifier(public_key.Oid.Value));
            Asn1StreamParser asp = new Asn1StreamParser(public_key.EncodedParameters.RawData);
            IAsn1Convertible ro;
            while ((ro = asp.ReadObject()) != null)
            {
                algorithm.AddObject(ro.ToAsn1Object());
            }
            return new DerSequence(algorithm, new DerBitString(public_key.EncodedKeyValue.RawData)).GetEncoded();
        }

        public static byte[] EncodeX509PublicKey (System.Security.Cryptography.X509Certificates.PublicKey public_key)
        {
            return EncodeX509PublicKey (public_key, false);
        }

        public static byte[] EncodeX509ECPublicKey (System.Security.Cryptography.X509Certificates.PublicKey public_key)
        {
            return EncodeX509PublicKey (public_key, true);
        }

        internal static System.Security.Cryptography.X509Certificates.PublicKey DecodeX509PublicKey (byte[] public_key_blob, bool ec_flag)
        {
            if (public_key_blob == null)
            {
                return null;
            }
            Asn1Sequence inner = Asn1Sequence.GetInstance(Asn1Object.FromByteArray (public_key_blob));
            Asn1Sequence algorithm = Asn1Sequence.GetInstance (inner[0]);
            DerObjectIdentifier oid = DerObjectIdentifier.GetInstance(algorithm[0]);
            TestKey (oid.Id, ec_flag);
            return new System.Security.Cryptography.X509Certificates.PublicKey (new System.Security.Cryptography.Oid (oid.Id),
                                                                                new System.Security.Cryptography.AsnEncodedData (algorithm[1].GetEncoded()),
                                                                                new System.Security.Cryptography.AsnEncodedData (DerBitString.GetInstance (inner[1]).GetBytes ()));
        }

        public static System.Security.Cryptography.X509Certificates.PublicKey DecodeX509PublicKey (byte[] public_key_blob)
        {
            return DecodeX509PublicKey (public_key_blob, false);
        }

        public static System.Security.Cryptography.X509Certificates.PublicKey DecodeX509ECPublicKey (byte[] public_key_blob)
        {
            return DecodeX509PublicKey (public_key_blob, true);
        }

        public static System.Security.Cryptography.X509Certificates.X509Certificate2[] BinaryListToCertificates (System.Collections.Generic.List<byte[]> blist)
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2[] certs = new System.Security.Cryptography.X509Certificates.X509Certificate2[blist.Count];
            int i = 0;
            foreach (byte[] b_arr in blist)
            {
                certs[i++] = new System.Security.Cryptography.X509Certificates.X509Certificate2(b_arr);
            }
            return i == 0 ? null : certs;
        }

        public static System.Collections.Generic.List<byte[]> CertificatesToBinaryList (System.Security.Cryptography.X509Certificates.X509Certificate2[] certs)
        {
            System.Collections.Generic.List<byte[]> blist = new System.Collections.Generic.List<byte[]>();
            if (certs != null) foreach (System.Security.Cryptography.X509Certificates.X509Certificate2 cert in certs)
            {
                blist.Add (cert.RawData);
            }
            return blist;
        }

        public static HashSet<PatternRestriction> SKSToPatternRestrictions (sbyte sks_value)
        {
            HashSet<PatternRestriction> pr = new HashSet<PatternRestriction> ();
            foreach(sbyte b in Enum.GetValues(typeof(PatternRestriction)))
            {
                if ((b & sks_value) != 0)
                {
                    pr.Add ((PatternRestriction) b);
                }
            }
            return pr;
        }

        public static sbyte PatternRestrictionsToSKS (HashSet<PatternRestriction> PatternRestrictions)
        {
            if (PatternRestrictions == null)
            {
            	return 0;
            }
            sbyte sks_value = 0;
            foreach(PatternRestriction pr in PatternRestrictions)
            {
            	sks_value |= (sbyte) pr;
            }
            return sks_value;
        }
    }
}