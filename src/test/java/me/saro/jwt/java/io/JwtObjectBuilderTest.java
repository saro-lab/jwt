package me.saro.jwt.java.io;

import io.jsonwebtoken.SignatureAlgorithm;
import me.saro.jwt.old.impl.DefaultKeyChain;
import me.saro.jwt.old.io.JwtBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] JwtBuilder")
public class JwtObjectBuilderTest {
    @Test
    @DisplayName("arguments check")
    public void t2() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new JwtBuilder(SignatureAlgorithm.RS384, DefaultKeyChain.create(SignatureAlgorithm.RS256)));

        JwtBuilder builder = new JwtBuilder(SignatureAlgorithm.RS256, DefaultKeyChain.create(SignatureAlgorithm.RS256));

        Assertions.assertThrows(IllegalArgumentException.class, () -> builder.header("kid", ""));
        Assertions.assertThrows(IllegalArgumentException.class, () -> builder.header("alg", ""));
        Assertions.assertThrows(IllegalArgumentException.class, () -> builder.header("", ""));

        Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim("exp", ""));
        Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim("iat", ""));
        Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim("", ""));
    }

    @Test
    @DisplayName("build")
    public void t3() {
        Assertions.assertDoesNotThrow(() -> {
            JwtBuilder builder = new JwtBuilder(SignatureAlgorithm.RS256, DefaultKeyChain.create(SignatureAlgorithm.RS256));
            builder.claim("name", "안녕");
            builder.build();
        });
    }
}
