package me.saro.jwt.java.io;

import io.jsonwebtoken.SignatureAlgorithm;
import me.saro.jwt.io.JwtBuilder;
import me.saro.jwt.model.KeyChain;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] JwtBuilder")
public class JwtBuilderTest {
    @Test
    @DisplayName("null check")
    public void t0() {
        Assertions.assertThrows(NullPointerException.class, () -> new JwtBuilder(null, null));
        Assertions.assertThrows(NullPointerException.class, () -> new JwtBuilder(SignatureAlgorithm.RS256, null));
        Assertions.assertThrows(NullPointerException.class, () -> new JwtBuilder(null, KeyChain.create(SignatureAlgorithm.RS256)));
    }

    @Test
    @DisplayName("arguments check")
    public void t2() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> new JwtBuilder(SignatureAlgorithm.RS384, KeyChain.create(SignatureAlgorithm.RS256)));

        JwtBuilder builder = new JwtBuilder(SignatureAlgorithm.RS256, KeyChain.create(SignatureAlgorithm.RS256));

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
            JwtBuilder builder = new JwtBuilder(SignatureAlgorithm.RS256, KeyChain.create(SignatureAlgorithm.RS256));
            builder.claim("name", "안녕");
            builder.build();
        });
    }
}
