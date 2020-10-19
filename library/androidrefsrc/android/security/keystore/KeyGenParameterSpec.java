package android.security.keystore;

import java.math.BigInteger;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public class KeyGenParameterSpec {
    
    public static class Builder {
        public Builder(String a, int b) {
            
        }
 
        public Builder setAlgorithmParameterSpec(AlgorithmParameterSpec g) {
            return this;
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
        public Builder setCertificateSerialNumber(BigInteger serial) {
            return this;
        }
        public Builder setCertificateNotBefore(Date date) {
            return this;
        }
        public Builder setCertificateSubject(X500Principal name) {
            return this;
        }
        public Builder setAttestationChallenge(byte[] challenge) {
            return this;
        }
        public AlgorithmParameterSpec build() {
            return null;
        }

    }
    
}
