package me.saro.jwt.java;


import me.saro.jwt.key.JwtKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static me.saro.jwt.JwtAlgorithm.*;

@DisplayName("[Java] Sample Validation Test - jwt.io")
public class SampleValidationTest {

    @Test
    @DisplayName("[Java] HS256 check jwt.io example")
    public void hs256() {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        Assertions.assertTrue(JwtKey.parseHashByText(HS256, "your-256-bit-secret").verify(jwt));
        Assertions.assertFalse(JwtKey.parseHashByText(HS256, "your-256-bit-secret-not").verify(jwt));
        System.out.println("HS256 jwt.io example - pass");
    }

    @Test
    @DisplayName("[Java] HS384 check jwt.io example")
    public void hs384() {
        String jwt = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh";
        Assertions.assertTrue(JwtKey.parseHashByText(HS384, "your-384-bit-secret").verify(jwt));
        Assertions.assertFalse(JwtKey.parseHashByText(HS384, "your-384-bit-secret-not").verify(jwt));
        System.out.println("HS384 jwt.io example - pass");
    }

    @Test
    @DisplayName("[Java] HS512 check jwt.io example")
    public void hs512() {
        String jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg";
        Assertions.assertTrue(JwtKey.parseHashByText(HS512, "your-512-bit-secret").verify(jwt));
        Assertions.assertFalse(JwtKey.parseHashByText(HS512, "your-512-bit-secret-not").verify(jwt));
        System.out.println("HS512 jwt.io example - pass");
    }

}
