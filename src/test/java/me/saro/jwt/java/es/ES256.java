package me.saro.jwt.java.es;

import me.saro.jwt.alg.es.JwtAlgorithmEs256;
import me.saro.jwt.alg.es.JwtAlgorithmEs384;
import me.saro.jwt.alg.es.JwtKeyEs;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] ES256")
public class ES256 {

    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var exJwtBody = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        var exJwtSign = "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
        var publicKey = (
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9" +
                "q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg=="
        );
        var privateKey = (
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2" +
                "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r" +
                "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G"
        );
        var es = new JwtAlgorithmEs256();
        var key = es.toJwtKey(publicKey + "\n" + privateKey);

        var newSign = es.signature(key, exJwtBody);

        System.out.println(Assertions.assertDoesNotThrow(() -> es.verify(key, exJwtBody + "." + exJwtSign)));
        System.out.println(Assertions.assertDoesNotThrow(() -> es.verify(key, exJwtBody + "." + newSign)));

        Assertions.assertThrows(JwtException.class, () -> es.verify(key, exJwtBody + "." + exJwtSign+"1"));
        Assertions.assertThrows(JwtException.class, () -> es.verify(key, exJwtBody + "." + newSign+"1"));
    }

    @Test
    @DisplayName("create / parse")
    public void t2() {
        var es = new JwtAlgorithmEs384();
        var key = (JwtKeyEs)es.genJwtKey();

        System.out.println(key.getKeyPair().getPublic().getAlgorithm());
        System.out.println(key.getKeyPair().getPrivate().getAlgorithm());
    }


}
