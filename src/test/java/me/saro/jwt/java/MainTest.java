package me.saro.jwt.java;

import me.saro.jwt.alg.es.JwtAlgorithmEs384;
import me.saro.jwt.alg.es.JwtKeyEs;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] MainTest")
public class MainTest {
    @Test
    @DisplayName("normal")
    public void t1() {
        var es = new JwtAlgorithmEs384();
        var key = (JwtKeyEs)es.genJwtKey();

        var body = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        var sig = es.signature(key, body);
        System.out.println(body + "." + sig);
        System.out.println(key.stringify());
    }
}
