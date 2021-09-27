package me.saro.jwt.java.model;

import io.jsonwebtoken.SignatureAlgorithm;
import me.saro.jwt.model.KeyChain;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

@DisplayName("[Java] KeyChain")
public class KeyChainTest {
    @Test
    @DisplayName("crypt success")
    public void t1() {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
        KeyChain kc = KeyChain.create(signatureAlgorithm);

        System.out.println(kc);

        String text = "안녕하세요. 간단한 암/복호화 test 입니다.";
        String encrypt = kc.encrypt(text);
        String decrypt = kc.decrypt(encrypt);

        System.out.println("--------");
        System.out.println(text);
        System.out.println(encrypt);

        Assertions.assertNotEquals(text, encrypt);
        Assertions.assertEquals(text, decrypt);
    }

    @Test
    @DisplayName("crypt exception")
    public void t2() {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
        KeyChain kc1 = KeyChain.create(signatureAlgorithm);
        KeyChain kc2 = KeyChain.create(signatureAlgorithm);

        System.out.println(kc1);
        System.out.println(kc2);

        String text = "안녕하세요. 간단한 암/복호화 test 입니다.";
        String encrypt = kc1.encrypt(text);

        Assertions.assertThrows(GeneralSecurityException.class, () -> kc2.decrypt(encrypt));
    }

    @Test
    @DisplayName("serialize and deserialize")
    public void t3() {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
        KeyChain kc1 = KeyChain.create(signatureAlgorithm);
        KeyChain kc2 = KeyChain.deserialize(kc1.serialize());

        System.out.println(kc1);
        System.out.println(kc2);

        String text = "안녕하세요. 간단한 암/복호화 test 입니다.";
        String encrypt = kc1.encrypt(text);
        String decrypt = kc2.decrypt(encrypt);

        System.out.println("--------");
        System.out.println(text);
        System.out.println(encrypt);

        Assertions.assertNotEquals(text, encrypt);
        Assertions.assertEquals(text, decrypt);
    }

}
