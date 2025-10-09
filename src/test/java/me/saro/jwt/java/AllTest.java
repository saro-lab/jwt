//package me.saro.jwt.java;
//
//import me.saro.jwt.key.JwtKey;
//import org.junit.jupiter.api.*;
//import static me.saro.jwt.key.JwtAlgorithm.*;
//
//import java.time.OffsetDateTime;
//import java.util.ArrayList;
//import java.util.Date;
//import java.util.List;
//
//@DisplayName("[Java] all test")
//@TestInstance(TestInstance.Lifecycle.PER_CLASS)
//@TestMethodOrder(MethodOrderer.DisplayName.class)
//public class AllTest {
//
//    List<JwtKey> createKeyList = new ArrayList<>();
//    List<String> stringKeyList = new ArrayList<>();
//    List<JwtKey> convertKeyList = new ArrayList<>();
//
//    @Test
//    @DisplayName("[Java] 01 created Keys")
//    public void test01() {
//        long start = System.currentTimeMillis();
//
//        // HS Algorithm
//        )
//        createKeyList.add(JwtKey.generateHash(HS256.newRandomKey());
//        createKeyList.add(HS256.newRandomJwtKey(20));
//        createKeyList.add(HS256.newRandomJwtKey(10, 40));
//        createKeyList.add(HS256.toKeyByText("HS256_4_key"));
//        createKeyList.add(HS384.newRandomKey());
//        createKeyList.add(HS384.newRandomJwtKey(20));
//        createKeyList.add(HS384.newRandomJwtKey(10, 40));
//        createKeyList.add(HS384.toKeyByText("HS384_4_key"));
//        createKeyList.add(HS512.newRandomKey());
//        createKeyList.add(HS512.newRandomJwtKey(20));
//        createKeyList.add(HS512.newRandomJwtKey(10, 40));
//        createKeyList.add(HS512.toKeyByText("HS512_4_key"));
//
//        // ES Algorithm
//        createKeyList.add(ES256.newRandomKey());
//        createKeyList.add(ES256.newRandomKey());
//        createKeyList.add(ES256.newRandomKey());
//        createKeyList.add(ES384.newRandomKey());
//        createKeyList.add(ES384.newRandomKey());
//        createKeyList.add(ES384.newRandomKey());
//        createKeyList.add(ES512.newRandomKey());
//        createKeyList.add(ES512.newRandomKey());
//        createKeyList.add(ES512.newRandomKey());
//
//        // PS Algorithm
//        createKeyList.add(PS256.newRandomKey());
//        createKeyList.add(PS256.newRandomJwtKey(2048));
//        createKeyList.add(PS256.newRandomJwtKey(3072));
//        createKeyList.add(PS256.newRandomJwtKey(4096));
//        createKeyList.add(PS384.newRandomKey());
//        createKeyList.add(PS384.newRandomJwtKey(2048));
//        createKeyList.add(PS384.newRandomJwtKey(3072));
//        createKeyList.add(PS384.newRandomJwtKey(4096));
//        createKeyList.add(PS512.newRandomKey());
//        createKeyList.add(PS512.newRandomJwtKey(2048));
//        createKeyList.add(PS512.newRandomJwtKey(3072));
//        createKeyList.add(PS512.newRandomJwtKey(4096));
//
//        // RS Algorithm
//        createKeyList.add(RS256.newRandomKey());
//        createKeyList.add(RS256.newRandomJwtKey(2048));
//        createKeyList.add(RS256.newRandomJwtKey(3072));
//        createKeyList.add(RS256.newRandomJwtKey(4096));
//        createKeyList.add(RS384.newRandomKey());
//        createKeyList.add(RS384.newRandomJwtKey(2048));
//        createKeyList.add(RS384.newRandomJwtKey(3072));
//        createKeyList.add(RS384.newRandomJwtKey(4096));
//        createKeyList.add(RS512.newRandomKey());
//        createKeyList.add(RS512.newRandomJwtKey(2048));
//        createKeyList.add(RS512.newRandomJwtKey(3072));
//        createKeyList.add(RS512.newRandomJwtKey(4096));
//
//        Assertions.assertEquals(45, createKeyList.size());
//        System.out.println("create " + createKeyList.size() + " keys - " + (System.currentTimeMillis() - start) + "ms");
//    }
//
//    @Test
//    @DisplayName("[Java] 02 stringify keys")
//    public void test02() {
//        Assertions.assertNotEquals(0, createKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
//
//        long start = System.currentTimeMillis();
//
//        createKeyList.forEach((key) -> stringKeyList.add(key.toString()) );
//
//        Assertions.assertEquals(45, stringKeyList.size());
//
//        stringKeyList.forEach(System.out::println);
//        System.out.println("pass stringify " + stringKeyList.size() + " keys - " + (System.currentTimeMillis() - start) + "ms");
//    }
//
//    @Test
//    @DisplayName("[Java] 03 convert string keys")
//    public void test03() {
//        Assertions.assertNotEquals(0, stringKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
//
//        long start = System.currentTimeMillis();
//
//        stringKeyList.forEach((key) -> convertKeyList.add(parseKey(key)));
//
//        Assertions.assertEquals(45, convertKeyList.size());
//
//        convertKeyList.forEach(System.out::println);
//        System.out.println("pass convert " + convertKeyList.size() + " keys - " + (System.currentTimeMillis() - start) + "ms");
//    }
//
//    @Test
//    @DisplayName("[Java] 04 expired")
//    public void test04() {
//        Assertions.assertNotEquals(0, createKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
//
//        long start = System.currentTimeMillis();
//
//        createKeyList.forEach((key) -> {
//            String jwt = createJwt(key)
//                    .expire(OffsetDateTime.now().minusMinutes(1))
//                    .build();
//            JwtException exception = Assertions.assertThrows(JwtException.class, () -> parseJwt(jwt, convertKeyList));
//            Assertions.assertEquals(JwtExceptionCode.DATE_EXPIRED, exception.getCode());
//        });
//
//        System.out.println("pass expired test - " + (System.currentTimeMillis() - start) + "ms");
//    }
//
//    @Test
//    @DisplayName("[Java] 05 not before")
//    public void test05() {
//        Assertions.assertNotEquals(0, createKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
//
//        long start = System.currentTimeMillis();
//
//        createKeyList.forEach((key) -> {
//            String jwt = createJwt(key)
//                    .notBefore(OffsetDateTime.now().plusDays(1))
//                    .build();
//            JwtException exception = Assertions.assertThrows(JwtException.class, () -> parseJwt(jwt, convertKeyList));
//            Assertions.assertEquals(JwtExceptionCode.DATE_BEFORE, exception.getCode());
//        });
//
//        System.out.println("pass not before test - " + (System.currentTimeMillis() - start) + "ms");
//    }
//
//    @Test
//    @DisplayName("[Java] 06 pass")
//    public void test06() {
//        Assertions.assertNotEquals(0, createKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
//
//        long start = System.currentTimeMillis();
//
//        createKeyList.forEach(key -> {
//            String jwt = createJwt(key)
//                    .build();
//            JwtNode node = Assertions.assertDoesNotThrow(() -> parseJwt(jwt, convertKeyList));
//            Assertions.assertEquals(key.getKid(), node.getKid());
//        });
//
//        System.out.println("pass test - " + (System.currentTimeMillis() - start) + "ms");
//    }
//
//    @Test
//    @DisplayName("[Java] 07 data")
//    public void test07() {
//        Assertions.assertNotEquals(0, createKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
//
//        long start = System.currentTimeMillis();
//
//        String issuer = "issuer1";
//        String subject = "subject2";
//        String audience = "audience3";
//        String id = "id4";
//        var boolData = true;
//        var boolData2 = "no";
//        var boolData3 = "1";
//        var boolData4 = "Y";
//        var boolData5 = "YeS";
//        var boolData6 = "N";
//        var intData1 = 1237890;
//        var intData2 = "-7890";
//        var longData1 = 1234567891110L;
//        var longData2 = "42345678911103";
//        Date issuedAt = new Date(OffsetDateTime.now().toEpochSecond() * 1000L);
//        long notBefore = OffsetDateTime.now().minusMinutes(1).toEpochSecond();
//        long expire = OffsetDateTime.now().plusHours(1).toEpochSecond();
//
//        createKeyList.forEach(key -> {
//            String jwt = createJwt(key)
//                    .issuer(issuer)
//                    .subject(subject)
//                    .audience(audience)
//                    .id(id)
//                    .claim("boolData", boolData)
//                    .claim("boolData2", boolData2)
//                    .claim("boolData3", boolData3)
//                    .claim("boolData4", boolData4)
//                    .claim("boolData5", boolData5)
//                    .claim("boolData6", boolData6)
//                    .claim("intData1", intData1)
//                    .claim("intData2", intData2)
//                    .claim("longData1", longData1)
//                    .claim("longData2", longData2)
//                    .claim("test", "test-value")
//                    .issuedAt(issuedAt)
//                    .notBefore(notBefore)
//                    .expire(expire)
//                    .build();
//            JwtNode node = Assertions.assertDoesNotThrow(() -> parseJwt(jwt, convertKeyList));
//            Assertions.assertEquals(key.getKid(), node.getKid());
//            Assertions.assertEquals(key.getAlgorithm().getAlgorithmFullName(), node.getAlgorithm());
//            Assertions.assertEquals(issuer, node.getIssuer());
//            Assertions.assertEquals(subject, node.getSubject());
//            Assertions.assertEquals(audience, node.getAudience());
//            Assertions.assertEquals(id, node.getId());
//            Assertions.assertEquals(boolData, node.claimBoolean("boolData"));
//            Assertions.assertEquals(false, node.claimBoolean("boolData2"));
//            Assertions.assertEquals(true, node.claimBoolean("boolData3"));
//            Assertions.assertEquals(true, node.claimBoolean("boolData4"));
//            Assertions.assertEquals(true, node.claimBoolean("boolData5"));
//            Assertions.assertEquals(false, node.claimBoolean("boolData6"));
//            Assertions.assertEquals(intData1, node.claimInt("intData1"));
//            Assertions.assertEquals(-7890, node.claimInt("intData2"));
//            Assertions.assertEquals(longData1, node.claimLong("longData1"));
//            Assertions.assertEquals(42345678911103L, node.claimLong("longData2"));
//            Assertions.assertEquals("test-value", node.claimString("test"));
//            Assertions.assertEquals(issuedAt, node.getIssuedAt());
//            Assertions.assertEquals(notBefore, node.getNotBeforeEpochSecond());
//            Assertions.assertEquals(expire, node.getExpireEpochSecond());
//            System.out.println("pass: " + node);
//        });
//
//        System.out.println("pass test - " + (System.currentTimeMillis() - start) + "ms");
//    }
//
//}
