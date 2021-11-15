package me.saro.jwt.java.hs;

import me.saro.jwt.alg.es.JwtAlgorithmEs384;
import me.saro.jwt.alg.es.JwtKeyEs;
import me.saro.jwt.alg.hs.JwtAlgorithmHs256;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] HS256")
public class HS256 {

    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var exJwtBody = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        var exJwtSign = "ypNASjsXTW6nmFdRxHAw-7s7tLMLj_jKknIXprDZkSs";
        var secret = "your-secret-key";

        var es = new JwtAlgorithmHs256();
        var key = es.getJwtKey(secret);

        var newJwtSign = es.signature(key, exJwtBody);

        Assertions.assertEquals(exJwtSign, newJwtSign);

        System.out.println(Assertions.assertDoesNotThrow(() -> es.verify(key, exJwtBody + "." + exJwtSign)));
        System.out.println(Assertions.assertDoesNotThrow(() -> es.verify(key, exJwtBody + "." + newJwtSign)));

        Assertions.assertThrows(JwtException.class, () -> es.verify(key, exJwtBody + "." + exJwtSign+"1"));
        Assertions.assertThrows(JwtException.class, () -> es.verify(key, exJwtBody + "." + newJwtSign+"1"));
    }

    @Test
    @DisplayName("normal")
    public void t2() {
        var es = new JwtAlgorithmEs384();
        var key = (JwtKeyEs)es.genJwtKey();

        System.out.println(key.getKeyPair().getPublic().getAlgorithm());
        System.out.println(key.getKeyPair().getPrivate().getAlgorithm());
    }


}
