package android.security.keystore;

public class KeyProperties {
    
    public static String KEY_ALGORITHM_EC = "EC";
    public static String KEY_ALGORITHM_RSA = "RSA";
    
    public static int PURPOSE_SIGN = 2;
    public static int PURPOSE_VERIFY = 4;
    public static int PURPOSE_DECRYPT = 8;
    
    public static String DIGEST_SHA256 = "256";
    public static String DIGEST_SHA384 = "256";
    public static String DIGEST_SHA512 = "256";
    public static String DIGEST_NONE   = "0";
    public static final String SIGNATURE_PADDING_RSA_PKCS1 = "PKCS1";
    
    public static final String  ENCRYPTION_PADDING_RSA_PKCS1 ="PKCS1";
    public static final String ENCRYPTION_PADDING_RSA_OAEP ="OAEP";

    
}
