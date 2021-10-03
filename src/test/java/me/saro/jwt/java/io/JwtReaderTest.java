package me.saro.jwt.java.io;

import io.jsonwebtoken.SignatureAlgorithm;
import me.saro.jwt.JwtKeyManager;
import me.saro.jwt.impl.DefaultJwtKeyManager;
import me.saro.jwt.io.JwtBuilder;
import me.saro.jwt.io.JwtReader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] JwtReader")
public class JwtReaderTest {
    @Test
    @DisplayName("read")
    public void t1() {
        String name = "안녕 hello !@#$";
        String encode = "안녕 hello !@#$";

        JwtKeyManager jwtKeyManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);
        JwtBuilder builder = jwtKeyManager.getJwtBuilder();
        builder.claim("name", name);
        builder.encryptClaim("encode", encode);
        String jwt = builder.build();

        System.out.println(jwt);

        JwtReader jwtReader = jwtKeyManager.parse(jwt);

        Assertions.assertEquals(name, jwtReader.claim("name"));
        Assertions.assertEquals(encode, jwtReader.decryptClaim("encode"));
    }
}
