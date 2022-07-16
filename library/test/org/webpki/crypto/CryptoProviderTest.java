package org.webpki.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

import java.security.spec.ECGenParameterSpec;

public class CryptoProviderTest {
    
    static final byte[] DATA2SIGN = {'S', 'i', 'g', 'n', ' ', 'm', 'e', '!'};
    
    static void roundTrip(KeyPair keyPair, String algorithm, boolean bc) throws Exception {
        Signature signer = bc ? Signature.getInstance(algorithm, "BC") : Signature.getInstance(algorithm);
        signer.initSign(keyPair.getPrivate());
        signer.update(DATA2SIGN);
        byte[] signature = signer.sign();
        Signature verifier = bc ? Signature.getInstance(algorithm, "BC") : Signature.getInstance(algorithm);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(DATA2SIGN);
        if (!verifier.verify(signature)) {
            throw new RuntimeException("Did not verify: " + algorithm + " bc=" + bc);
        }
        System.out.println("Succeeded: Algorithm=" + algorithm +
                           ", BC=" + bc +
                           ", Private key=" + keyPair.getPrivate().getClass().getCanonicalName());
    }

    public static void main(String[] args) {
        try {
            Provider bc = (Provider) Class
                    .forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
                    .getDeclaredConstructor().newInstance();
            Security.addProvider(bc);

            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec("secp256r1");
            generator.initialize(eccgen, new SecureRandom());
            KeyPair bcECKeyPair = generator.generateKeyPair();

            generator = KeyPairGenerator.getInstance("EC");
            eccgen = new ECGenParameterSpec("secp256r1");
            generator.initialize(eccgen, new SecureRandom());
            KeyPair defaultECKeyPair = generator.generateKeyPair();

            roundTrip(bcECKeyPair, "SHA256withECDSA", true);
            roundTrip(defaultECKeyPair, "SHA256withECDSA", false);
            roundTrip(bcECKeyPair, "SHA256withECDSA", false);
            roundTrip(defaultECKeyPair, "SHA256withECDSA", true);

            generator = KeyPairGenerator.getInstance("ed25519", "BC");
            KeyPair bcEdDSAKeyPair = generator.generateKeyPair();
            generator = KeyPairGenerator.getInstance("ed25519");
            KeyPair defaultEdDSAKeyPair = generator.generateKeyPair();
            roundTrip(bcEdDSAKeyPair, "ed25519", true);
            roundTrip(defaultEdDSAKeyPair, "ed25519", false);
            roundTrip(bcEdDSAKeyPair, "ed25519", false);
            // Fails
            roundTrip(defaultEdDSAKeyPair, "ed25519", true);

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }

    }

}
