package cbor_api_demo;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.webpki.cbor.CBORAsymKeyDecrypter;
import org.webpki.cbor.CBORAsymKeyEncrypter;
import org.webpki.cbor.CBORKeyPair;
import org.webpki.cbor.CBORDecoder;

import org.webpki.crypto.ContentEncryptionAlgorithms;
import org.webpki.crypto.KeyEncryptionAlgorithms;

import org.webpki.util.HexaDecimal;
import org.webpki.util.UTF8;

public class EncryptionDemo {
    
    // Message encoded in UTF-8.
    static final byte[] SECRET_MESSAGE = UTF8.encode("A very secret message");
    
    // X25519 private key in COSE format.
    static final byte[] X25519_PRIVATE_KEY = HexaDecimal.decode(
            "a401012004215820e99a0cef205894960d9b1c05978513dccb" +
            "42a13bfbced523a51b8a117ad5f00c2358207317e5f3a11599" +
            "caab474ee65843427f517fe4d8b99add55886c84441e90d6f0");
    
    public static void main(String[] args) {
        // Get keys in Java format.
        KeyPair keyPair = CBORKeyPair.convert(CBORDecoder.decode(X25519_PRIVATE_KEY));
        PrivateKey receiverKey = keyPair.getPrivate();
        PublicKey senderKey = keyPair.getPublic();
        
        // Encrypt data using CEF.
        byte[] encryptionObject = new CBORAsymKeyEncrypter(senderKey,
                                                           KeyEncryptionAlgorithms.ECDH_ES,
                                                           ContentEncryptionAlgorithms.A256GCM)
                .encrypt(SECRET_MESSAGE).encode();
        
        // Decrypt data using CEF.
        byte[] decryptedData = new CBORAsymKeyDecrypter(receiverKey)
                .decrypt(CBORDecoder.decode(encryptionObject));
        
        // Assume that the data is a string encoded in UTF-8.
        String secretMessage = UTF8.decode(decryptedData);
        System.out.println(secretMessage);
//@begin@
new CborDocumentLog(args[0], "#sample.program.key#", CBORDecoder.decode(X25519_PRIVATE_KEY));
new CborDocumentLog(args[0], "#sample.program.hex#", encryptionObject = 
new CborDocumentLog().checkForChanges(encryptionObject, HexaDecimal.decode(
        "a5010302a201381807a3010120042158203e9c03b4e2ccb023272fe0f1a5a41" +
        "4645a7e5a0952a3da8199ba46812603ee1a08504ac80be51285309b93b8f4cc" +
        "38f6b8ba094c9fbd6e151bad2af177dd33820a55115b48dcffcf88dce70b217" +
        "3d6c368b2cfe802521c")));
new CborDocumentLog(args[0], "#sample.program.diagnostic#", CBORDecoder.decode(encryptionObject));
new CborDocumentLog(args[0], args[1], "#sample.program#");
//@end@
    }
}
