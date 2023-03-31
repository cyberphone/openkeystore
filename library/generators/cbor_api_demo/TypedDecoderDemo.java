package cbor_api_demo;

import java.io.IOException;

import java.security.GeneralSecurityException;

import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORString;
import org.webpki.cbor.CBORTag;
import org.webpki.cbor.CBORTypedDecoder;
import org.webpki.cbor.CBORTypedDecoderCache;

public class TypedDecoderDemo {
    
    // Typed decoder one.
    public static class ObjectOne extends CBORTypedDecoder {

        int number;
        
        static final String OBJECT_ID   = "https://example.com/object-one";
        static final CBORObject INT_KEY = new CBORInteger(1);
        
        @Override
        protected void decode(CBORObject cborBody) throws IOException, GeneralSecurityException {
            number = cborBody.getMap().getObject(INT_KEY).getInt();
        }

        @Override
        public String getObjectId() {
            return OBJECT_ID;
        }
    }
    
    // Typed decoder two.
    public static class ObjectTwo extends CBORTypedDecoder {
        
        static final String OBJECT_ID = "https://example.com/object-two";
        
        String justAString;

        @Override
        protected void decode(CBORObject cborBody) throws IOException, GeneralSecurityException {
            justAString = cborBody.getString();
        }

        @Override
        public String getObjectId() {
            return OBJECT_ID;
        }
    }
    
    // Register the decoders.
    static final CBORTypedDecoderCache decoderCache = new CBORTypedDecoderCache()
            .addToCache(ObjectOne.class)
            .addToCache(ObjectTwo.class);

    
    public static void main(String[] args) {
        try {
            // Create typed CBOR messages.
            byte[] objectOne = new CBORTag(ObjectOne.OBJECT_ID,
                    new CBORMap().setObject(ObjectOne.INT_KEY, new CBORInteger(-343)))
                        .encode();
            
            byte[] objectTwo = new CBORTag(ObjectTwo.OBJECT_ID, 
                    new CBORString("Hi there!"))
                        .encode();
            
            // Decode and instantiate.
            CBORTypedDecoder decodedObject = decoderCache.decode(CBORObject.decode(objectOne));
            
            // Dispatch to the proper handler for the associated decoder.
            switch (decodedObject.getObjectId()) {
                case ObjectOne.OBJECT_ID:
                    System.out.println("Number=" + ((ObjectOne)decodedObject).number);
                    break;
                    
                default: 
                    throw new IOException("Unexpected");
            }
//@begin@
new CborDocumentLog(args[0], "#sample.program.diagnostic#", CBORObject.decode(objectOne));
new CborDocumentLog(args[0], args[1], "#sample.program#");
//@end@

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
