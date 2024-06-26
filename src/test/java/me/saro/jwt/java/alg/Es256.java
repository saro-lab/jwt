package me.saro.jwt.java.alg;

import me.saro.jwt.alg.es.JwtEs256;
import me.saro.jwt.core.Jwt;
import me.saro.jwt.core.JwtClaims;
import me.saro.jwt.core.JwtKey;
import me.saro.jwt.exception.JwtException;
import me.saro.jwt.exception.JwtExceptionCode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

@DisplayName("[Java] ES256")
public class Es256 {

    public JwtEs256 alg() {
        return Jwt.es256();
    }

    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
        var publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==";
        var privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G";

        var alg = alg();
        var key = alg.toJwtKey(publicKey, privateKey);

        System.out.println("example");
        Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));
        System.out.println("example jwt toJwt - pass");

        Assertions.assertThrows(JwtException.class, () -> alg.toJwtClaims(jwt, alg.newRandomJwtKey()));
        System.out.println("example jwt error text - pass");
    }

    @Test
    @DisplayName("kid test")
    public void t2() {
        var alg = alg();
        var keys = new HashMap<String, JwtKey>();
        var jwtList = new ArrayList<String>();

        for (int i = 0 ; i < 30 ; i++) {
            var kid = UUID.randomUUID().toString();
            var key = alg.newRandomJwtKey();
            keys.put(kid, key);

            var jc = JwtClaims.create();
            jc.id("abc");
            jc.expire(OffsetDateTime.now().plusMinutes(30));

            jwtList.add(Assertions.assertDoesNotThrow(() -> alg.toJwt(key, jc, kid)));
        }

        jwtList.parallelStream().forEach(jwt -> {
            var jh = alg.toJwtHeader(jwt);

            var key = keys.get(jh.getKid());
            Assertions.assertNotNull(key);

            var jc = Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));
            Assertions.assertThrows(JwtException.class, () -> alg.toJwtClaims(jwt, alg.newRandomJwtKey()));

            Assertions.assertEquals(jc.getId(), "abc");
        });
        System.out.println("done");
    }

    @Test
    @DisplayName("expire test")
    public void t3() {
        var alg = alg();
        var key = alg.newRandomJwtKey();

        var jcp = JwtClaims.create();
        jcp.expire(OffsetDateTime.now().plusMinutes(30));
        Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(alg.toJwt(key, jcp), key));

        var jce = JwtClaims.create();
        jce.expire(OffsetDateTime.now().minusMinutes(30));
        Assertions.assertThrowsExactly(JwtException.class, () -> alg.toJwtClaims(alg.toJwt(key, jce), key), JwtExceptionCode.DATE_EXPIRED.name());
    }

    @Test
    @DisplayName("not before test")
    public void t4() {
        var alg = alg();
        var key = alg.newRandomJwtKey();

        var jcp = JwtClaims.create();
        jcp.notBefore(OffsetDateTime.now().minusMinutes(30));
        Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(alg.toJwt(key, jcp), key));

        var jce = JwtClaims.create();
        jce.notBefore(OffsetDateTime.now().plusMinutes(30));
        Assertions.assertThrowsExactly(JwtException.class, () -> alg.toJwtClaims(alg.toJwt(key, jce), key), JwtExceptionCode.DATE_EXPIRED.name());
    }

    @Test
    @DisplayName("data test")
    public void t5() {
        var alg = alg();
        var key = alg.newRandomJwtKey();

        var jc = JwtClaims.create();
        jc.issuedAt(OffsetDateTime.now());
        jc.notBefore(OffsetDateTime.now().minusMinutes(1));
        jc.expire(OffsetDateTime.now().plusMinutes(30));
        jc.id("jti value");
        jc.issuer("iss value");
        jc.subject("sub value");
        jc.audience("aud value");
        jc.claim("custom", "custom value");

        System.out.println(jc);

        var jwt = alg.toJwt(key, jc);

        System.out.println(jwt);

        var njc = Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));

        System.out.println(njc);

        Assertions.assertEquals(njc.getId(), "jti value");
        Assertions.assertEquals(njc.getIssuer(), "iss value");
        Assertions.assertEquals(njc.getSubject(), "sub value");
        Assertions.assertEquals(njc.getAudience(), "aud value");
        Assertions.assertEquals(njc.claim("custom"), "custom value");
    }
}
