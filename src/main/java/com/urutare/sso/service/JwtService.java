package com.urutare.sso.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.urutare.sso.utils.KeyLoader;
import jakarta.validation.constraints.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;

@Service
public class JwtService {

    @Value("${private.key.path}")
    private String privateKeyPath;

    @Value("${public.key.path}")
    private String publicKeyPath;

    @Value("${private.key.password}")
    private String privateKeyPassword;

    @Value("${jwt.issuer}")
    private String issuer;

    private RSAPublicKey getPublicKey() throws Exception {
        Resource resource = new ClassPathResource(publicKeyPath);
        return (RSAPublicKey) KeyLoader.loadPublicKey(resource.getInputStream());
    }

    private RSAPrivateKey getPrivateKey() throws Exception {
        Resource resource = new ClassPathResource(privateKeyPath);
        return (RSAPrivateKey) KeyLoader.loadPrivateKey(resource.getInputStream(), privateKeyPassword);
    }

    public String generateToken(String subject) throws Exception {
        RSAPrivateKey privateKey = getPrivateKey();
        Algorithm rsaAlgorithm = Algorithm.RSA256(null, privateKey);

        return JWT.create()
                .withSubject(subject)
                .withIssuer(issuer)
                .withExpiresAt(new Date(System.currentTimeMillis() + 86400000)) // 1 day expiration
                .sign(rsaAlgorithm);
    }

    public void verifyJwtToken(String token) {
        try {
            RSAPublicKey publicKey = getPublicKey();
            System.out.println("Public Key: " + publicKey.toString());
            Algorithm rsaAlgorithm = Algorithm.RSA256(publicKey, null);

            JWTVerifier jwtVerifier = JWT.require(rsaAlgorithm).withIssuer(issuer).build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);

            // Print decoded JWT details for debugging
            System.out.println("Token Verified Successfully!");
            System.out.println("Issuer: " + decodedJWT.getIssuer());
            System.out.println("Subject: " + decodedJWT.getSubject());
            System.out.println("Expiration: " + decodedJWT.getExpiresAt());

        } catch (JWTVerificationException ex) {
            System.out.println("JWTVerificationException: " + ex.getMessage());
            throw new JWTVerificationException("Invalid Token");
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
            throw new JWTVerificationException(ex.getMessage());
        }
    }

    @NotNull
    public String getTokenPayload(String token) {
        // Verify the token
        verifyJwtToken(token);
        String[] chunks = token.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        return new String(decoder.decode(chunks[1]));
    }
}
