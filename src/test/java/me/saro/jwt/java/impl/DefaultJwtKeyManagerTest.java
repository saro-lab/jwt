package me.saro.jwt.java.impl;

import io.jsonwebtoken.SignatureAlgorithm;
import me.saro.jwt.JwtKeyManager;
import me.saro.jwt.impl.DefaultJwtKeyManager;
import me.saro.jwt.model.KeyChain;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] DefaultJwtKeyManager")
public class DefaultJwtKeyManagerTest {
    @Test
    @DisplayName("key not rotate")
    public void t1() {
        JwtKeyManager jwtKeyManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);
        KeyChain kc1 = jwtKeyManager.getKeyChain();
        KeyChain kc2 = jwtKeyManager.getKeyChain();

        System.out.println("not rotate kc1 ---------------------");
        System.out.println(kc1);
        System.out.println("not rotate kc2 ---------------------");
        System.out.println(kc2);

        Assertions.assertEquals(kc1, kc2);
    }

    @Test
    @DisplayName("key rotate")
    public void t2() {
        JwtKeyManager jwtKeyManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256);
        KeyChain kc1 = jwtKeyManager.getKeyChain();
        jwtKeyManager.rotate();
        KeyChain kc2 = jwtKeyManager.getKeyChain();

        System.out.println("not rotate kc1 ---------------------");
        System.out.println(kc1);
        System.out.println("not rotate kc2 ---------------------");
        System.out.println(kc2);

        Assertions.assertNotEquals(kc1, kc2);
    }

    @Test
    @DisplayName("parameter pass")
    public void t3() {
        Assertions.assertDoesNotThrow(() -> DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 3));
        Assertions.assertDoesNotThrow(() -> DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 3, 0));
        Assertions.assertDoesNotThrow(() -> DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 4, 1));
    }

    @Test
    @DisplayName("parameter error")
    public void t4() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 2));
        Assertions.assertThrows(IllegalArgumentException.class, () -> DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 3, -1));
    }

}
