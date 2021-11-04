package me.saro.jwt.java;

import io.jsonwebtoken.SignatureAlgorithm;
import me.saro.jwt.old.JwtKeyManager;
import me.saro.jwt.old.impl.DefaultJwtKeyManager;
import me.saro.jwt.old.io.JwtReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@DisplayName("[Java] MainTest")
public class MainTest {
    @Test
    @DisplayName("normal")
    public void t1() {
        String name = "안녕 hello !@#$";
        String encode = "안녕 hello !@#$";

        JwtKeyManager jwtKeyManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);
        String jwt = jwtKeyManager.getJwtBuilder()
            .claim("name", name)
            .encryptClaim("encode", encode)
            .issuedAtNow()
            .expireMinutes(30)
            .id("id")
            .subject("sub")
            .issuer("iss")
            .build();

        System.out.println("jwt: " + jwt);

        String header = new String(Base64.getDecoder().decode(jwt.split("\\.")[0]));
        System.out.println("header: " + header);

        String payload = new String(Base64.getDecoder().decode(jwt.split("\\.")[1]));
        System.out.println("payload: " + payload);

        JwtReader jwtReader = jwtKeyManager.parse(jwt);

        Assertions.assertEquals(jwtReader.claim("name"), name);
        Assertions.assertEquals(jwtReader.decryptClaim("encode"), encode);
    }

    @Test
    @DisplayName("signature pass and error")
    public void t2() {
        JwtKeyManager m1 = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);
        JwtKeyManager m2 = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);

        String jwt = m1.getJwtBuilder().claim("text", "hello").build();

        Assertions.assertDoesNotThrow(() -> {
            JwtReader reader = m1.parse(jwt);
            System.out.println(reader.<String>claim("text"));
        });

        Assertions.assertThrows(SecurityException.class, () -> {
            JwtReader reader = m2.parse(jwt);
            System.out.println(reader.<String>claim("text"));
        });
    }

    @Test
    @DisplayName("example")
    public void t0() {
        // algorithm: RS256, key rotation queue size: 3, key rotation minutes: 30
        // key stored [rotation minutes (30) * queue size (3)] = 90 minutes
        JwtKeyManager jwtKeyManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 3, 30);

        String jwt = jwtKeyManager.getJwtBuilder()
            .encryptClaim("jti", "1234")
            .subject("sub")
            .issuer("iss")
            .issuedAtNow()
            .expireMinutes(30)
            .build();

        System.out.println("jwt: " + jwt);

        String header = new String(Base64.getDecoder().decode(jwt.split("\\.")[0]));
        System.out.println("header: " + header);

        String payload = new String(Base64.getDecoder().decode(jwt.split("\\.")[1]));
        System.out.println("payload: " + payload);

        JwtReader jwtReader = jwtKeyManager.parse(jwt);

        Map<String, Object> result = new HashMap<>();
        result.put("id", jwtReader.decryptClaim("jti"));
        result.put("subject", jwtReader.getSubject());
        result.put("issuer", jwtReader.getIssuer());
        result.put("issuedAt", jwtReader.getIssuedAt());
        result.put("expire", jwtReader.getExpire());
        System.out.println("result: " + result);
    }
}
