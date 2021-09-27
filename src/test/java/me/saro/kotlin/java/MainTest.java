package me.saro.kotlin.java;

import io.jsonwebtoken.SignatureAlgorithm;
import java.lang.SecurityException;
import me.saro.jwt.JwtKeyManager;
import me.saro.jwt.impl.DefaultJwtKeyManager;
import me.saro.jwt.io.JwtBuilder;
import me.saro.jwt.io.JwtReader;
import me.saro.jwt.model.ClaimName;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

@DisplayName("[Java] JwtReader")
public class MainTest {
    @Test
    @DisplayName("normal")
    public void t1() {
        String name = "안녕 hello !@#$";
        String encode = "안녕 hello !@#$";

        JwtKeyManager jwtKeyManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);
        JwtBuilder builder = jwtKeyManager.getJwtBuilder();
        builder.claim("name", name);
        builder.encryptClaim("encode", encode);
        builder.setIssuedAtNow();
        builder.setExpireMinutes(30);
        builder.claim(ClaimName.id, "id");
        builder.claim(ClaimName.subject, "sub");
        builder.claim(ClaimName.issuer, "iss");
        String jwt = builder.build();

        System.out.println("- JWT");
        System.out.println(jwt);
        System.out.println("- header / payload");
        Arrays.asList(jwt.split("\\.")).stream().limit(2)
                .map(e -> new String(Base64.getDecoder().decode(e.replace('-', '+').replace('_', '/'))))
                .forEach(System.out::println);

        JwtReader jwtReader = jwtKeyManager.parse(jwt);

        Assertions.assertEquals(jwtReader.claim("name").toString(), name);
        Assertions.assertEquals(jwtReader.decryptClaim("encode").toString(), encode);
    }

    @Test
    @DisplayName("signature pass and error")
    public void t2() {
        JwtKeyManager m1 = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);
        JwtKeyManager m2 = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);

        String jwt = m1.getJwtBuilder().claim("text", "hello").build();

        Assertions.assertDoesNotThrow(() -> {
            JwtReader reader = m1.parse(jwt);
            System.out.println(reader.claim("text"));
        });

        Assertions.assertThrows(SecurityException.class, () -> {
            JwtReader reader = m2.parse(jwt);
            System.out.println(reader.claim("text"));
        });
    }
}
