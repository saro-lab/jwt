package me.saro.jwt.java.es;

import me.saro.jwt.alg.es.JwtEs384;
import me.saro.jwt.alg.hs.JwtHs384;
import me.saro.jwt.core.JwtKey;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

@DisplayName("[Java] ES384")
public class ES384 {

    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var exJwtBody = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        var exJwtSign = "VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj";
        var publicKey = (
                "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+" +
                "Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii" +
                "1D3jaW6pmGVJFhodzC31cy5sfOYotrzF"
        );
        var privateKey = (
                "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p" +
                "E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz" +
                "MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw" +
                "8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU="
        );
        var alg = new JwtEs384();
        var key = alg.parseJwtKey(publicKey + " " + privateKey);

        var newJwtSign = alg.signature(exJwtBody, key);

        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign, key)));
        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign, key)));

        Assertions.assertThrows(Exception.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign+"1", key));
        Assertions.assertThrows(Exception.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign+"1", key));
    }

    @Test
    @DisplayName("normal")
    public void t2() {
        var alg = new JwtEs384();
        var key1 = alg.randomJwtKey();
        var key2 = alg.randomJwtKey();
        var key3 = alg.parseJwtKey(key1.stringify());

        System.out.println("key1: " + key1);
        System.out.println("key2: " + key2);
        System.out.println("key3: " + key3);

        var jwtObject = alg.createJwtObject();
        jwtObject.audience("test aud");
        jwtObject.id("id test");

        System.out.println("jwtObject: " + jwtObject);

        var jwt1 = alg.toJwt(jwtObject, key1);
        var jwt2 = alg.toJwt(jwtObject, key2);
        var jwt3 = alg.toJwt(jwtObject, key3);

        System.out.println("jwt key1: " + jwt1);
        System.out.println("jwt key2: " + jwt2);
        System.out.println("jwt key3: " + jwt3);

        Assertions.assertNotEquals(jwt1, jwt2);

        Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(jwt1, key1));
        Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(jwt2, key2));
        Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(jwt3, key3));

        Assertions.assertThrows(JwtException.class, () -> alg.toJwtObjectWithVerify(jwt2, key1));
    }

    @Test
    @DisplayName("key store")
    public void t3() {
        var alg = new JwtEs384();

        var keyStore = new ConcurrentHashMap<String, JwtKey>();
        var jwtList = new ArrayList<String>();

        for (var i = 0 ; i < 10 ; i++) {
            var kid = Integer.toString(i);
            var key = alg.randomJwtKey();
            keyStore.put(kid, key);
            System.out.println("create jwt key : kid["+kid+"] : " + key);

            var jwtObject = alg.createJwtObject();
            jwtObject.kid(kid);
            jwtObject.id("test id");
            System.out.println(jwtObject);

            var jwt = alg.toJwt(jwtObject, key);
            System.out.println(jwt);

            jwtList.add(jwt);
        }

        for (var i = 0 ; i < jwtList.size() ; i++) {
            var jwtObject = alg.toJwtObjectWithVerifyOrNull(jwtList.get(i), kid -> keyStore.get(kid));
            Assertions.assertNotNull(jwtObject);
            System.out.println("pass: " + jwtObject);
        }

        var wrongKeyStore = new ConcurrentHashMap<String, JwtKey>();
        wrongKeyStore.put("1", new JwtHs384().randomJwtKey());
        for (var i = 0 ; i < jwtList.size() ; i++) {
            var jwtObject = alg.toJwtObjectWithVerifyOrNull(jwtList.get(i), kid -> wrongKeyStore.get(kid));
            Assertions.assertNull(jwtObject);
            System.out.println("wrong: " + jwtList.get(i));
        }

    }

    @Test
    @DisplayName("expire")
    public void t4() {
        var alg = new JwtEs384();

        var key = alg.randomJwtKey();
        System.out.println(key);

        var validJwtObject = alg.createJwtObject();
        validJwtObject.expire(OffsetDateTime.now().plusDays(1));
        System.out.println(validJwtObject);
        var validJwt = alg.toJwt(validJwtObject, key);
        System.out.println(validJwt);
        Assertions.assertTrue(alg.verify(validJwt, key));

        var expireJwtObject = alg.createJwtObject();
        expireJwtObject.expire(OffsetDateTime.now().minusDays(1));
        System.out.println(expireJwtObject);
        var expireJwt = alg.toJwt(expireJwtObject, key);
        System.out.println(expireJwt);
        Assertions.assertFalse(alg.verify(expireJwt, key));
    }
}