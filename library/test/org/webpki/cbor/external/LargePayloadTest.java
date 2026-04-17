// LargePayloadTest.java

package org.webpki.cbor.external;

import java.io.IOException;
import java.io.InputStream;

import java.net.URI;

import java.util.Arrays;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;

import java.security.MessageDigest;

import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORString;


public class LargePayloadTest {

  static final CBORString FILE_KEY = new CBORString("file");
  static final CBORString SHA256_KEY = new CBORString("sha256");

  static final int CHUNK_SIZE = 1024;

  public static void main(String[] args) {
    try {
      // Perform an HTTP request and get a stream to the returned body.
      HttpRequest request = HttpRequest.newBuilder()
        .uri(new URI("https://cyberphone.github.io/cbor-core/large-payload/payload.bin"))
        .GET()
        .build();
      HttpResponse<InputStream> response = HttpClient.newBuilder()
        .build()
        .send(request, BodyHandlers.ofInputStream());
      InputStream inputStream = response.body();

      // Begin by reading and decoding the CBOR metadata.
      // Note: the SEQUENCE_MODE makes decoding stop after reading a CBOR object.
      CBORMap metaData = new CBORDecoder(inputStream, 
                                         CBORDecoder.SEQUENCE_MODE,
                                         10000).decodeWithOptions().getMap();

      // The rest of the payload is assumed to hold the attached file.
      // Initialize the SHA256 digest system.
      MessageDigest hashFunction = MessageDigest.getInstance("SHA256");

      // Now read (in modest chunks), the potentially large attached file.
      byte[] chunk = new byte[CHUNK_SIZE];
      int fileSize = 0;
      for (int n; (n = inputStream.read(chunk)) > 0; fileSize += n) {
        // Each chunk updates the SHA256 calculation.
        hashFunction.update(chunk, 0, n);
        /////////////////////////////////////////////////////
        // Store the chunk in an application-specific way. //
        /////////////////////////////////////////////////////
      }
      inputStream.close();
    
      // All is read, now get the completed digest.
      byte[] calculatedSha256 = hashFunction.digest();
      // Verify the hash.
      if (Arrays.compare(calculatedSha256, metaData.get(SHA256_KEY).getBytes()) != 0) {
        throw new IOException("Failed on SHA256");
      }

      // We actually did it!
      System.out.printf("\nSuccessfully received: %s (%d)\n", metaData.get(FILE_KEY).getString(), fileSize);

    } catch (Exception e) {
      // Something is wrong...
      e.printStackTrace();
    }
  }
}
