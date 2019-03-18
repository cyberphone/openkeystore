using System;
using System.IO;

using org.webpki.sks.ws.client.BouncyCastle.Utilities.IO;

namespace org.webpki.sks.ws.client.BouncyCastle.Asn1
{
	public class DerOctetStringParser
		: Asn1OctetStringParser
	{
		private readonly DefiniteLengthInputStream stream;

		internal DerOctetStringParser(
			DefiniteLengthInputStream stream)
		{
			this.stream = stream;
		}

		public Stream GetOctetStream()
		{
			return stream;
		}

		public Asn1Object ToAsn1Object()
		{
			try
			{
				return new DerOctetString(stream.ToArray());
			}
			catch (IOException e)
			{
				throw new InvalidOperationException("IOException converting stream to byte array: " + e.Message, e);
			}
		}
	}
}
