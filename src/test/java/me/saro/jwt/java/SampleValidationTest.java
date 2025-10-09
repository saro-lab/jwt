package me.saro.jwt.java;


import me.saro.jwt.node.Jwt;
import me.saro.jwt.node.JwtNode;
import me.saro.jwt.key.JwtHashKey;
import me.saro.jwt.key.JwtKey;
import me.saro.jwt.key.JwtPairPrivateKey;
import me.saro.jwt.key.JwtPairPublicKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static me.saro.jwt.key.JwtAlgorithm.*;

@DisplayName("[Java] Sample Validation Test - jwt.io")
public class SampleValidationTest {

    @Test
    @DisplayName("[Java] HS256 check jwt.io example")
    public void hs256() {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        JwtNode node = Jwt.parseOrNull(jwt);
        JwtHashKey trueKey = JwtKey.parseHashByText(HS256, "your-256-bit-secret");
        JwtHashKey falseKey = JwtKey.parseHashByText(HS256, "your-256-bit-secret-not");
        // text
        Assertions.assertTrue(trueKey.verify(jwt));
        Assertions.assertFalse(falseKey.verify(jwt));
        // node
        Assertions.assertNotNull(node);
        Assertions.assertTrue(node.verify(trueKey));
        Assertions.assertFalse(node.verify(falseKey));
    }

    @Test
    @DisplayName("[Java] HS384 check jwt.io example")
    public void hs384() {
        String jwt = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh";
        JwtNode node = Jwt.parseOrNull(jwt);
        JwtHashKey trueKey = JwtKey.parseHashByText(HS384, "your-384-bit-secret");
        JwtHashKey falseKey = JwtKey.parseHashByText(HS384, "your-384-bit-secret-not");
        // text
        Assertions.assertTrue(trueKey.verify(jwt));
        Assertions.assertFalse(falseKey.verify(jwt));
        // node
        Assertions.assertNotNull(node);
        Assertions.assertTrue(node.verify(trueKey));
        Assertions.assertFalse(node.verify(falseKey));
    }

    @Test
    @DisplayName("[Java] HS512 check jwt.io example")
    public void hs512() {
        String jwt = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg";
        JwtNode node = Jwt.parseOrNull(jwt);
        JwtHashKey trueKey = JwtKey.parseHashByText(HS512, "your-512-bit-secret");
        JwtHashKey falseKey = JwtKey.parseHashByText(HS512, "your-512-bit-secret-not");
        // text
        Assertions.assertTrue(trueKey.verify(jwt));
        Assertions.assertFalse(falseKey.verify(jwt));
        // node
        Assertions.assertNotNull(node);
        Assertions.assertTrue(node.verify(trueKey));
        Assertions.assertFalse(node.verify(falseKey));
    }

    @Test
    @DisplayName("[Java] ES256 check jwt.io example")
    public void es256() {
        String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
        String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==";
        String privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G";
        JwtNode node = Jwt.parseOrNull(jwt);
        JwtPairPublicKey jwtPublicKey = JwtKey.parsePairPublicByPem(ES256, publicKey);
        JwtPairPrivateKey jwtPrivateKey = JwtKey.parsePairPrivateByPem(ES256, privateKey);

        // text
        Assertions.assertTrue(jwtPublicKey.verify(jwt));
        Assertions.assertFalse(jwtPublicKey.verify("00000"+jwt.substring(5)));
        // node
        Assertions.assertNotNull(node);
        Assertions.assertTrue(node.verify(jwtPublicKey));
        // mix
        String newJwt = node.toBuilder().id("userId").build(jwtPrivateKey);
        Assertions.assertTrue(jwtPublicKey.verify(newJwt));
    }

    @Test
    @DisplayName("[Java] ES384 check jwt.io example")
    public void es384() {
        String jwt = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj";
        String publicKey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii1D3jaW6pmGVJFhodzC31cy5sfOYotrzF";
        String privateKey = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/pE9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=";
        JwtNode node = Jwt.parseOrNull(jwt);
        JwtPairPublicKey jwtPublicKey = JwtKey.parsePairPublicByPem(ES384, publicKey);
        JwtPairPrivateKey jwtPrivateKey = JwtKey.parsePairPrivateByPem(ES384, privateKey);

        // text
        Assertions.assertTrue(jwtPublicKey.verify(jwt));
        Assertions.assertFalse(jwtPublicKey.verify("00000"+jwt.substring(5)));
        // node
        Assertions.assertNotNull(node);
        Assertions.assertTrue(node.verify(jwtPublicKey));
        // mix
        String newJwt = node.toBuilder().id("userId").build(jwtPrivateKey);
        Assertions.assertTrue(jwtPublicKey.verify(newJwt));
    }

    @Test
    @DisplayName("[Java] ES512 check jwt.io example")
    public void es512() {
        String jwt = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk";
        String publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZPDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib476MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwMAl8G7CqwoJOsW7Kddns=";
        String privateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew==";
        JwtNode node = Jwt.parseOrNull(jwt);
        JwtPairPublicKey jwtPublicKey = JwtKey.parsePairPublicByPem(ES512, publicKey);
        JwtPairPrivateKey jwtPrivateKey = JwtKey.parsePairPrivateByPem(ES512, privateKey);

        // text
        Assertions.assertTrue(jwtPublicKey.verify(jwt));
        Assertions.assertFalse(jwtPublicKey.verify("00000"+jwt.substring(5)));
        // node
        Assertions.assertNotNull(node);
        Assertions.assertTrue(node.verify(jwtPublicKey));
        // mix
        String newJwt = node.toBuilder().id("userId").build(jwtPrivateKey);
        Assertions.assertTrue(jwtPublicKey.verify(newJwt));
    }

}

