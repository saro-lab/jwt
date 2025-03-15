package me.saro.jwt.java;

import me.saro.jwt.Jwt;
import me.saro.jwt.JwtNode;
import org.junit.jupiter.api.*;

import java.time.OffsetDateTime;

@DisplayName("[Java] single example test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.DisplayName.class)
public class ExampleSingleKeyTest {

    @Test
    @DisplayName("[Java] single key test")
    public void test() {
        var es256 = Jwt.ES256;
        var key = es256.newRandomKey();

        String issuer = "issuer1";
        String subject = "subject2";
        String audience = "audience3";
        String id = "id4";
        var boolData = true;
        var boolData2 = "no";
        long expire = OffsetDateTime.now().plusHours(1).toEpochSecond();

        // create jwt
        String jwt = key.createJwt()
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .id(id)
                .claim("boolData", boolData)
                .claim("boolData2", boolData2)
                .expire(expire)
                .build();

        System.out.println("jwt: " + jwt);

        // parse jwt
        JwtNode node = Assertions.assertDoesNotThrow(() -> key.parseJwt(jwt));
        Assertions.assertEquals(key.getAlgorithm().getAlgorithmFullName(), node.getAlgorithm());
        Assertions.assertEquals(issuer, node.getIssuer());
        Assertions.assertEquals(subject, node.getSubject());
        Assertions.assertEquals(audience, node.getAudience());
        Assertions.assertEquals(id, node.getId());
        Assertions.assertEquals(boolData, node.claimBoolean("boolData"));
        Assertions.assertEquals(false, node.claimBoolean("boolData2"));
        Assertions.assertEquals(expire, node.getExpireEpochSecond());

        System.out.println("jwt node: " + node);
    }
}
