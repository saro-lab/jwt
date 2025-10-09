package me.saro.jwt.java;


import me.saro.jwt.JwtUtil;
import me.saro.jwt.key.JwtKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static me.saro.jwt.JwtAlgorithm.HS256;

@DisplayName("[Java] Sample Validation Test - jwt.io")
public class SampleValidationTest {

    @Test
    @DisplayName("[Java] HS256 check jwt.io example")
    public void hs256() {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        System.out.println(
                JwtUtil.encodeBase64String(JwtKey.parseHashByText(HS256, "your-256-bit-secret").createSignature("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ".getBytes(StandardCharsets.UTF_8)))
        );

        Assertions.assertTrue(JwtKey.parseHashByText(HS256, "your-256-bit-secret").verify(jwt));
        Assertions.assertFalse(JwtKey.parseHashByText(HS256, "your-256-bit-secret-not").verify(jwt));
        System.out.println("HS256 jwt.io example - pass");
    }

}
