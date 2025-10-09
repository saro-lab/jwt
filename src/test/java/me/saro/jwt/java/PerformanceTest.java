//package me.saro.jwt.java;
//
//import me.saro.jwt.old.Jwt;
//import me.saro.jwt.old.JwtAlgorithm;
//import me.saro.jwt.old.JwtKey;
//import me.saro.jwt.old.JwtNode;
//import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//
//@DisplayName("[Java] Performance Test")
//public class PerformanceTest {
//
//    @Test
//    @DisplayName("[Java] ES dynamic keys test")
//    public void d_es() {
//        dynamicKeys(100, Jwt.ES256, Jwt.ES384, Jwt.ES512);
//    }
//
//    @Test
//    @DisplayName("[Java] HS dynamic keys test")
//    public void d_hs() {
//        dynamicKeys(1000, Jwt.HS256, Jwt.HS384, Jwt.HS512);
//    }
//
//    @Test
//    @DisplayName("[Java] PS dynamic keys test")
//    public void d_ps() {
//        dynamicKeys(10, Jwt.PS256, Jwt.PS384, Jwt.PS512);
//    }
//
//    @Test
//    @DisplayName("[Java] RS dynamic keys test")
//    public void d_rs() {
//        dynamicKeys(10, Jwt.RS256, Jwt.RS384, Jwt.RS512);
//    }
//
//    @Test
//    @DisplayName("[Java] ES fixed keys test")
//    public void f_es() {
//        fixedKeys(1000, Jwt.ES256, Jwt.ES384, Jwt.ES512);
//    }
//
//    @Test
//    @DisplayName("[Java] HS fixed keys test")
//    public void f_hs() {
//        fixedKeys(5000, Jwt.HS256, Jwt.HS384, Jwt.HS512);
//    }
//
//    @Test
//    @DisplayName("[Java] PS fixed keys test")
//    public void f_ps() {
//        fixedKeys(300, Jwt.PS256, Jwt.PS384, Jwt.PS512);
//    }
//
//    @Test
//    @DisplayName("[Java] RS fixed keys test")
//    public void f_rs() {
//        fixedKeys(500, Jwt.RS256, Jwt.RS384, Jwt.RS512);
//    }
//
//    private void dynamicKeys(int loop, JwtAlgorithm... algs) {
//        for (JwtAlgorithm alg : algs) {
//            long start = System.currentTimeMillis();
//            for (int i = 0 ; i < loop ; i++) {
//                JwtKey key = alg.newRandomKey();
//                var jwt = Jwt.createJwt(key)
//                        .subject("1234567890")
//                        .claim("name", "John Doe")
//                        .claim("admin", true)
//                        .claim("iat", 1516239022)
//                        .build();
//
//                JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseJwt(jwt, nodeKey -> key));
//                Assertions.assertEquals("1234567890", node.getSubject());
//                Assertions.assertEquals("John Doe", node.claimString("name"));
//                Assertions.assertEquals(true, node.claimBoolean("admin"));
//                Assertions.assertEquals(1516239022, node.claimInt("iat"));
//            }
//            System.out.println(alg.getAlgorithmFullName() + " dynamic keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms");
//        }
//    }
//
//    private void fixedKeys(int loop, JwtAlgorithm... algs) {
//        for (JwtAlgorithm alg : algs) {
//            JwtKey key = alg.newRandomKey();
//            long start = System.currentTimeMillis();
//            for (int i = 0 ; i < loop ; i++) {
//                var jwt = Jwt.createJwt(key)
//                        .subject("1234567890")
//                        .claim("name", "John Doe")
//                        .claim("admin", true)
//                        .claim("iat", 1516239022)
//                        .build();
//
//                JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseJwt(jwt, nodeKey -> key));
//                Assertions.assertEquals("1234567890", node.getSubject());
//                Assertions.assertEquals("John Doe", node.claimString("name"));
//                Assertions.assertEquals(true, node.claimBoolean("admin"));
//                Assertions.assertEquals(1516239022, node.claimInt("iat"));
//            }
//            System.out.println(alg.getAlgorithmFullName() + " fixed keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms");
//        }
//    }
//}
