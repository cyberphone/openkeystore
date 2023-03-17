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
        try {
            // Create CBOR data to be signed.
            CBORMap dataToBeSigned = new CBORMap()
                .setObject(HELLO_LABEL, new CBORString("Hello CBOR World!"))
                .setObject(ARRAY_LABEL, new CBORArray()
                    .addObject(new CBORFloatingPoint(-4.5))
                    .addObject(new CBORBoolean(true)));
            
            // Sign and encode CBOR.
            byte[] signedData = new CBORHmacSigner(HMAC_KEY, HmacAlgorithms.HMAC_SHA256)
                .sign(SIGNATURE_LABEL, dataToBeSigned).encode();
new CborDocumentLog(args[0], "#sample.program.hex#", signedData);
            
            // Decode CBOR and validate signature.
            CBORMap decodedCbor = new CBORHmacValidator(HMAC_KEY)
                .validate(SIGNATURE_LABEL, CBORObject.decode(signedData)).getMap();
new CborDocumentLog(args[0], "#sample.program.diagnostic#", decodedCbor);
new CborDocumentLog(args[0], args[1], "#sample.program#");
            // Fetch a map item.
            String greatings = decodedCbor.getObject(HELLO_LABEL).getString();
            
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
