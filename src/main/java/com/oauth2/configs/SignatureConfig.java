package com.oauth2.configs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.oauth2.signature.MacSecuritySigner;
import com.oauth2.signature.RsaKeyPublicSecuritySigner;
import com.oauth2.signature.RsaSecuritySigner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SignatureConfig {

    @Bean
    public MacSecuritySigner macSecuritySigner() {
        return new MacSecuritySigner();
    }

    @Bean
    public OctetSequenceKey octetSequenceKey() throws JOSEException {
        OctetSequenceKey octetSequenceKey = new OctetSequenceKeyGenerator(256)
                .keyID("macKey")
                .algorithm(JWSAlgorithm.HS256)
                .generate();
        return octetSequenceKey;
    }

    @Bean
    public RsaSecuritySigner rsaSecuritySigner() {
        return new RsaSecuritySigner();
    }

    @Bean
    public RSAKey rsaKey() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("rsaKey")
                .algorithm(JWSAlgorithm.RS512)
                .generate();
        return rsaKey;
    }

    @Bean
    public RsaKeyPublicSecuritySigner rsaPublicSecuritySigner() {
        return new RsaKeyPublicSecuritySigner();
    }
}
