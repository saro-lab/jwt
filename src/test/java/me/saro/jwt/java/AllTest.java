package me.saro.jwt.java;

import me.saro.jwt.key.*;
import me.saro.jwt.node.Jwt;
import me.saro.jwt.node.JwtNode;
import org.junit.jupiter.api.*;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static me.saro.jwt.key.JwtAlgorithm.*;

@DisplayName("[Java] all test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.DisplayName.class)
public class AllTest {

    List<JwtHashKey> hashKeyList = new ArrayList<>();
    List<JwtKeyPair> keyPairList = new ArrayList<>();
    List<List<String>> hashKeyListText = new ArrayList<>();
    List<List<String>> keyPairListText = new ArrayList<>();

    List<JwtSignatureKey> signatureKeyList = new ArrayList<>();
    List<JwtVerifyKey> verifyKeyList = new ArrayList<>();

    @Test
    @DisplayName("[Java] 01 created Keys")
    public void test01() {
        long start = System.currentTimeMillis();

        // HS Algorithm
        for (JwtAlgorithm alg: List.of(HS256, HS384, HS512)) {
            hashKeyList.add(JwtKey.generateHash(alg, 1));
            hashKeyList.add(JwtKey.generateHash(alg, 32));
            hashKeyList.add(JwtKey.generateHash(alg, 64));
            hashKeyList.add(JwtKey.parseHashByText(alg, "abcd"));
            hashKeyList.add(JwtKey.parseHashByHex(alg, "A162c364"));
            hashKeyList.add(JwtKey.parseHashByBase64(alg, "YWJjZA=="));
        }

        for (JwtAlgorithm alg: List.of(ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512)) {
            keyPairList.add(JwtKey.generateKeyPair(alg));
            keyPairList.add(JwtKey.generateKeyPair(alg));
            keyPairList.add(JwtKey.generateKeyPair(alg));
        }

        System.out.println("create " + (hashKeyList.size() + keyPairList.size()) + " keys - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 02 stringify keys")
    public void test02() {
        Assertions.assertNotEquals(0, hashKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
        Assertions.assertNotEquals(0, keyPairList.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        hashKeyList.forEach((key) -> hashKeyListText.add(List.of(key.getAlgorithm().name(), key.toBase64())) );
        keyPairList.forEach((key) -> keyPairListText.add(List.of(key.getPublic().getAlgorithm().name(), key.getPublic().toBase64(), key.getPrivate().toBase64())) );

        System.out.println("stringify " + (hashKeyListText.size() + keyPairListText.size())  + " keys - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 03 convert string keys")
    public void test03() {
        Assertions.assertNotEquals(0, hashKeyListText.size(), "This function cannot be tested independently. Please run the entire test.");
        Assertions.assertNotEquals(0, keyPairListText.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        hashKeyListText.forEach(key -> {
            JwtHashKey hashKey = JwtKey.parseHashByBase64(JwtAlgorithm.valueOf(key.get(0)), key.get(1));
            signatureKeyList.add(hashKey);
            verifyKeyList.add(hashKey);
        });
        keyPairListText.forEach(key -> {
            JwtAlgorithm alg = JwtAlgorithm.valueOf(key.get(0));
            JwtPairPublicKey publicKey = JwtKey.parsePairPublicByPem(alg, key.get(1));
            JwtPairPrivateKey privateKey = JwtKey.parsePairPrivateByPem(alg, key.get(2));
            signatureKeyList.add(privateKey);
            verifyKeyList.add(publicKey);
        });

        System.out.println("convert " + (signatureKeyList.size()) + " keys - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 04 expired")
    public void test04() {
        Assertions.assertNotEquals(0, signatureKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
        Assertions.assertNotEquals(0, verifyKeyList.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        for (int i = 0 ; i < signatureKeyList.size() ; i++) {
            String jwt = Jwt.builder().expire(OffsetDateTime.now().minusMinutes(1)).build(signatureKeyList.get(i));
            Assertions.assertFalse(Jwt.parseOrThrow(jwt).verify(verifyKeyList.get(i)));
        }

        System.out.println("pass expired test - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 05 not before")
    public void test05() {
        Assertions.assertNotEquals(0, signatureKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
        Assertions.assertNotEquals(0, verifyKeyList.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        for (int i = 0 ; i < signatureKeyList.size() ; i++) {
            String jwt = Jwt.builder().notBefore(OffsetDateTime.now().plusDays(1)).build(signatureKeyList.get(i));
            Assertions.assertFalse(Jwt.parseOrThrow(jwt).verify(verifyKeyList.get(i)));
        }

        System.out.println("pass not before test - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 06 pass")
    public void test06() {
        Assertions.assertNotEquals(0, signatureKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
        Assertions.assertNotEquals(0, verifyKeyList.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        for (int i = 0 ; i < signatureKeyList.size() ; i++) {
            String jwt = Jwt.builder().build(signatureKeyList.get(i));
            Assertions.assertTrue(Jwt.parseOrThrow(jwt).verify(verifyKeyList.get(i)));
        }

        System.out.println("pass test - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 07 data")
    public void test07() {
        Assertions.assertNotEquals(0, signatureKeyList.size(), "This function cannot be tested independently. Please run the entire test.");
        Assertions.assertNotEquals(0, verifyKeyList.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        String issuer = "issuer1";
        String subject = "subject2";
        String audience = "audience3";
        String id = "id4";
        var boolData = true;
        var boolData2 = "no";
        var boolData3 = "1";
        var boolData4 = "Y";
        var boolData5 = "YeS";
        var boolData6 = "N";
        var intData1 = 1237890;
        var intData2 = "-7890";
        var longData1 = 1234567891110L;
        var longData2 = "42345678911103";
        Date issuedAt = new Date(OffsetDateTime.now().toEpochSecond() * 1000L);
        long notBefore = OffsetDateTime.now().minusMinutes(1).toEpochSecond();
        long expire = OffsetDateTime.now().plusHours(1).toEpochSecond();

        for (int i = 0 ; i < signatureKeyList.size() ; i++) {
            JwtSignatureKey signatureKey = signatureKeyList.get(i);
            JwtVerifyKey verifyKey = verifyKeyList.get(i);

            String jwt = Jwt.builder()
                    .kid(Integer.toString(i))
                    .issuer(issuer)
                    .subject(subject)
                    .audience(audience)
                    .id(id)
                    .claim("boolData", boolData)
                    .claim("boolData2", boolData2)
                    .claim("boolData3", boolData3)
                    .claim("boolData4", boolData4)
                    .claim("boolData5", boolData5)
                    .claim("boolData6", boolData6)
                    .claim("intData1", intData1)
                    .claim("intData2", intData2)
                    .claim("longData1", longData1)
                    .claim("longData2", longData2)
                    .claim("test", "test-value")
                    .issuedAt(issuedAt)
                    .notBefore(notBefore)
                    .expire(expire)
                    .build(signatureKey);

            JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseOrThrow(jwt));
            Assertions.assertTrue(node.verify(verifyKey));
            Assertions.assertEquals(Integer.toString(i), node.getKid());
            Assertions.assertEquals(signatureKey.getAlgorithm().name(), node.getAlgorithm());
            Assertions.assertEquals(issuer, node.getIssuer());
            Assertions.assertEquals(subject, node.getSubject());
            Assertions.assertEquals(audience, node.getAudience());
            Assertions.assertEquals(id, node.getId());
            Assertions.assertEquals(boolData, node.claimBoolean("boolData"));
            Assertions.assertEquals(false, node.claimBoolean("boolData2"));
            Assertions.assertEquals(true, node.claimBoolean("boolData3"));
            Assertions.assertEquals(true, node.claimBoolean("boolData4"));
            Assertions.assertEquals(true, node.claimBoolean("boolData5"));
            Assertions.assertEquals(false, node.claimBoolean("boolData6"));
            Assertions.assertEquals(intData1, node.claimInt("intData1"));
            Assertions.assertEquals(-7890, node.claimInt("intData2"));
            Assertions.assertEquals(longData1, node.claimLong("longData1"));
            Assertions.assertEquals(42345678911103L, node.claimLong("longData2"));
            Assertions.assertEquals("test-value", node.claimString("test"));
            Assertions.assertEquals(issuedAt, node.getIssuedAt());
            Assertions.assertEquals(notBefore, node.getNotBeforeEpochSecond());
            Assertions.assertEquals(expire, node.getExpireEpochSecond());
            System.out.println("pass: " + node);
        }

        System.out.println("pass test - " + (System.currentTimeMillis() - start) + "ms");
    }

}
