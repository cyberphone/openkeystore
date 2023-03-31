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
    
    // Typed decoder 1.
    public static class DecoderOne extends CBORTypedDecoder {

        int number;
        
        static final String OBJECT_ID   = "https://example.com/object-1";
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
    
    // Typed decoder 2.
    public static class DecoderTwo extends CBORTypedDecoder {
        
        static final String OBJECT_ID = "https://example.com/object-2";
        
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
    static final CBORTypedDecoderCache schemaCache = new CBORTypedDecoderCache()
            .addToCache(DecoderOne.class)
            .addToCache(DecoderTwo.class);

    
    public static void main(String[] args) {
        try {
            // Create typed CBOR messages.
            byte[] objectOne = new CBORTag(DecoderOne.OBJECT_ID,
                    new CBORMap().setObject(DecoderOne.INT_KEY, new CBORInteger(-343)))
                        .encode();
            
            byte[] objectTwo = new CBORTag(DecoderTwo.OBJECT_ID, 
                    new CBORString("Hi there!"))
                        .encode();
            
            // Decode and instantiate.
            CBORTypedDecoder typedDecoder = schemaCache.decode(CBORObject.decode(objectOne));
            
            // Dispatch to the proper handler for the associated decoder.
            switch (typedDecoder.getObjectId()) {
                case DecoderOne.OBJECT_ID:
                    System.out.println("Number=" + ((DecoderOne)typedDecoder).number);
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
