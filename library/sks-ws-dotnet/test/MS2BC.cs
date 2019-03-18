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
namespace org.webpki.sks.ms2bc
{
    using org.webpki.sks.ws.client;

    public static class MS2BC
    {
        public static Org.BouncyCastle.Crypto.AsymmetricKeyParameter BCPublicKey(this System.Security.Cryptography.X509Certificates.PublicKey public_key)
        {
 			Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo subinfo = Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo.GetInstance (Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray (Conversions.EncodeX509PublicKey(public_key))));
            return Org.BouncyCastle.Security.PublicKeyFactory.CreateKey (subinfo);
        }
    }
}
