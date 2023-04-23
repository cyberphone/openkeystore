package cbor_api_demo;

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORBoolean;
import org.webpki.cbor.CBORFloatingPoint;
import org.webpki.cbor.CBORHmacSigner;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORString;

import org.webpki.crypto.HmacAlgorithms;

import org.webpki.util.HexaDecimal;

public class SignatureDemo {
    
    static final byte[] HMAC_KEY = HexaDecimal.decode(
            "7fdd851a3b9d2dafc5f0d00030e22b9343900cd42ede4948568a4a2ee655291a");
    
    static final CBORInteger HELLO_LABEL     = new CBORInteger(1);
    static final CBORInteger ARRAY_LABEL     = new CBORInteger(2);
    static final CBORInteger SIGNATURE_LABEL = new CBORInteger(-1);
    
    public static void main(String[] args) {
        // Create CBOR data to be signed.
        CBORMap dataToBeSigned = new CBORMap()
            .set(HELLO_LABEL, new CBORString("Hello Signed CBOR World!"))
            .set(ARRAY_LABEL, new CBORArray()
                .add(new CBORFloatingPoint(-4.5))
                .add(new CBORBoolean(true)));
        
        // Sign data using CSF.
        byte[] signatureObject = new CBORHmacSigner(HMAC_KEY, HmacAlgorithms.HMAC_SHA256)
            .sign(SIGNATURE_LABEL, dataToBeSigned).encode();
        
        // Validate CSF object.
        CBORMap decodedCbor = new CBORHmacValidator(HMAC_KEY)
            .validate(SIGNATURE_LABEL, CBORObject.decode(signatureObject)).getMap();
//@begin@
new CborDocumentLog(args[0], "#sample.program.hex#", signatureObject);
new CborDocumentLog(args[0], "#sample.program.diagnostic#", decodedCbor);
new CborDocumentLog(args[0], args[1], "#sample.program#");
//@end@

        // Fetch a map item.
        String greatings = decodedCbor.get(HELLO_LABEL).getString();
        System.out.println(greatings);
    }
}
