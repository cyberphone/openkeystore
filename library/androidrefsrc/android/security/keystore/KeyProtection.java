package android.security.keystore;

import java.security.KeyStore.ProtectionParameter;

public class KeyProtection {
    
    public KeyProtection() {
        
    }
    
    public static class Builder {
        public Builder(int purpose) {
            
        }
        public Builder setDigests(String... digests) {
            return this;
        }
        public Builder setSignaturePaddings(String... paddings) {
            return this;
        }
        public Builder setEncryptionPaddings(String... paddings) {
            return this;
        }
        public ProtectionParameter build() {
            return null;
        }
    }
}
