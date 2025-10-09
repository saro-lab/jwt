package me.saro.jwt.java;

import me.saro.jwt.key.JwtAlgorithm;
import me.saro.jwt.key.JwtHashKey;
import me.saro.jwt.key.JwtKey;
import me.saro.jwt.key.JwtKeyPair;
import me.saro.jwt.node.Jwt;
import me.saro.jwt.node.JwtNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static me.saro.jwt.key.JwtAlgorithm.*;

@DisplayName("[Java] Performance Test")
public class PerformanceTest {

    @Test
    @DisplayName("[Java] ES dynamic keys test")
    public void d_es() {
        dynamicKeysPair(100, ES256, ES384, ES512);
    }

    @Test
    @DisplayName("[Java] HS dynamic keys test")
    public void d_hs() {
        dynamicKeysHash(1000, HS256, HS384, HS512);
    }

    @Test
    @DisplayName("[Java] PS dynamic keys test")
    public void d_ps() {
        dynamicKeysPair(10, PS256, PS384, PS512);
    }

    @Test
    @DisplayName("[Java] RS dynamic keys test")
    public void d_rs() {
        dynamicKeysPair(10, RS256, RS384, RS512);
    }

    @Test
    @DisplayName("[Java] ES fixed keys test")
    public void f_es() {
        fixedKeysPair(1000, ES256, ES384, ES512);
    }

    @Test
    @DisplayName("[Java] HS fixed keys test")
    public void f_hs() {
        fixedKeysHash(5000, HS256, HS384, HS512);
    }

    @Test
    @DisplayName("[Java] PS fixed keys test")
    public void f_ps() {
        fixedKeysPair(300, PS256, PS384, PS512);
    }

    @Test
    @DisplayName("[Java] RS fixed keys test")
    public void f_rs() {
        fixedKeysPair(500, RS256, RS384, RS512);
    }

    private void dynamicKeysHash(int loop, JwtAlgorithm... algs) {
        for (JwtAlgorithm alg : algs) {
            long start = System.currentTimeMillis();
            for (int i = 0 ; i < loop ; i++) {
                JwtHashKey key = JwtKey.generateHash(alg, 32);
                var jwt = Jwt.builder()
                        .subject("1234567890")
                        .claim("name", "John Doe")
                        .claim("admin", true)
                        .claim("iat", 1516239022)
                        .build(key);

                JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseOrThrow(jwt));
                Assertions.assertTrue(node.verify(key));
                Assertions.assertEquals("1234567890", node.getSubject());
                Assertions.assertEquals("John Doe", node.claimString("name"));
                Assertions.assertEquals(true, node.claimBoolean("admin"));
                Assertions.assertEquals(1516239022, node.claimInt("iat"));
            }
            System.out.println(alg.name() + " dynamic keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms");
        }
    }

    private void fixedKeysHash(int loop, JwtAlgorithm... algs) {
        for (JwtAlgorithm alg : algs) {
            JwtHashKey key = JwtKey.generateHash(alg, 32);
            long start = System.currentTimeMillis();
            for (int i = 0 ; i < loop ; i++) {
                var jwt = Jwt.builder()
                        .subject("1234567890")
                        .claim("name", "John Doe")
                        .claim("admin", true)
                        .claim("iat", 1516239022)
                        .build(key);

                JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseOrThrow(jwt));
                Assertions.assertTrue(node.verify(key));
                Assertions.assertEquals("1234567890", node.getSubject());
                Assertions.assertEquals("John Doe", node.claimString("name"));
                Assertions.assertEquals(true, node.claimBoolean("admin"));
                Assertions.assertEquals(1516239022, node.claimInt("iat"));
            }
            System.out.println(alg.name() + " fixed keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms");
        }
    }

    private void dynamicKeysPair(int loop, JwtAlgorithm... algs) {
        for (JwtAlgorithm alg : algs) {
            long start = System.currentTimeMillis();
            for (int i = 0 ; i < loop ; i++) {
                JwtKeyPair key = JwtKey.generateKeyPair(alg);
                var jwt = Jwt.builder()
                        .subject("1234567890")
                        .claim("name", "John Doe")
                        .claim("admin", true)
                        .claim("iat", 1516239022)
                        .build(key.getPrivate());

                JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseOrThrow(jwt));
                Assertions.assertTrue(node.verify(key.getPublic()));
                Assertions.assertEquals("1234567890", node.getSubject());
                Assertions.assertEquals("John Doe", node.claimString("name"));
                Assertions.assertEquals(true, node.claimBoolean("admin"));
                Assertions.assertEquals(1516239022, node.claimInt("iat"));
            }
            System.out.println(alg.name() + " dynamic keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms");
        }
    }

    private void fixedKeysPair(int loop, JwtAlgorithm... algs) {
        for (JwtAlgorithm alg : algs) {
            JwtKeyPair key = JwtKey.generateKeyPair(alg);
            long start = System.currentTimeMillis();
            for (int i = 0 ; i < loop ; i++) {
                var jwt = Jwt.builder()
                        .subject("1234567890")
                        .claim("name", "John Doe")
                        .claim("admin", true)
                        .claim("iat", 1516239022)
                        .build(key.getPrivate());

                JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseOrThrow(jwt));
                Assertions.assertTrue(node.verify(key.getPublic()));
                Assertions.assertEquals("1234567890", node.getSubject());
                Assertions.assertEquals("John Doe", node.claimString("name"));
                Assertions.assertEquals(true, node.claimBoolean("admin"));
                Assertions.assertEquals(1516239022, node.claimInt("iat"));
            }
            System.out.println(alg.name() + " fixed keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms");
        }
    }
}
