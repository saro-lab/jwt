package me.saro.jwt.java;

import me.saro.jwt.Jwt;
import me.saro.jwt.JwtNode;
import me.saro.jwt.exception.JwtException;
import me.saro.jwt.store.JwtKeyStoreMirror;
import me.saro.jwt.store.JwtKeyStoreProvider;
import org.junit.jupiter.api.*;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

@DisplayName("[Java] key store example test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.DisplayName.class)
public class ExampleKeyStoreTest {

    private JwtKeyStoreProvider providerServer;
    private JwtKeyStoreMirror mirrorServer;
    private String database = "";

    @Test
    @DisplayName("[Java] 01 create provider server")
    public void test01() throws InterruptedException {
        // provider server
        // jwt: create [OK] paser [OK]
        // key: issue [OK] export [OK] import [only in builder]

        // jwt provider server
        // create and export keys
        providerServer = Jwt
                .createKeyStoreProvider()
                .algorithm(Jwt.ES512)
                // expire time default 0, 0 is never expire
                .keyExpireTime(Duration.ofHours(3))
                // provider and mirror sync time (default 0)
                // - before sync time, the key can only be parseJwt() not createJwt()
                .keySyncTime(Duration.ofSeconds(5))
                .build();
        System.out.println("create provider server");

        // make 3 keys
        providerServer.issue();
        providerServer.issue();
        Thread.sleep(1000); // test for delay 1 second
        providerServer.issue();
        Assertions.assertEquals(3, providerServer.getAllKeysForMonitor().size());
        System.out.println("issue 3 keys:\n" + providerServer.getAllKeysForMonitor());
        Assertions.assertEquals(3, providerServer.getNotReadyKeysForMonitor().size());
        System.out.println(providerServer.getState());

        // export to database
        database = providerServer.exports();
        System.out.println("export to database\n" + database);
    }

    @Test
    @DisplayName("[Java] 02 create mirror server")
    public void test02() throws InterruptedException {
        if (providerServer == null) {
            test01();
        }

        // mirror server
        // jwt: create [OK] paser [OK]
        // key: issue [NO] export [OK] import [OK]

        // jwt mirror server
        // create and import keys
        mirrorServer = Jwt
                .createKeyStoreMirror()
                .imports(database)
                .build();
        System.out.println("create mirror server");

        // exports, imports test
        String exports = mirrorServer.exports();
        Assertions.assertEquals(database, exports);
        mirrorServer.imports(exports);
        Assertions.assertEquals(exports, mirrorServer.exports());
        Assertions.assertEquals(3, mirrorServer.getAllKeysForMonitor().size());
        System.out.println("exports, imports test\n" + exports);
        Assertions.assertEquals(3, mirrorServer.getNotReadyKeysForMonitor().size());
        System.out.println(mirrorServer.getState());
    }

    @Test
    @DisplayName("[Java] 03 jwt ready test (mixed provider and mirror)")
    public void test03() throws InterruptedException {
        if (mirrorServer == null) {
            test02();
        }

        // provider server
        // jwt: create [OK] paser [OK]
        // key: issue [OK] export [OK] import [only in builder]

        // mirror server
        // jwt: create [OK] paser [OK]
        // key: issue [NO] export [OK] import [OK]


        // cannot create, only parse (before sync time)
        Assertions.assertThrows(JwtException.class, () -> providerServer.createJwt().build());
        Assertions.assertThrows(JwtException.class, () -> mirrorServer.createJwt().build());

        // wait for key sync time -> .keySyncTime(Duration.ofSeconds(5))
        Thread.sleep(5000);

        // ready
        Assertions.assertDoesNotThrow(() -> providerServer.createJwt().build());
        Assertions.assertDoesNotThrow(() -> mirrorServer.createJwt().build());
    }

    @Test
    @DisplayName("[Java] 04 jwt (create / parse) test (mixed provider and mirror)")
    public void test04() throws InterruptedException {
        if (mirrorServer == null) {
            test03();
        }

        // jwts list
        List<String> list = new ArrayList<>();

        // test data
        String issuer = "issuer1";
        String subject = "subject2";
        String audience = "audience3";
        String id = "id4";
        boolean boolData = true;
        String boolData2 = "no";
        long expire = OffsetDateTime.now().plusHours(1).toEpochSecond();

        // create jwt by provider
        for (int i = 0 ; i < 10 ; i++) {
            String jwt = providerServer.createJwt().issuer(issuer)
                    .subject(subject)
                    .audience(audience)
                    .id(id)
                    .claim("boolData", boolData)
                    .claim("boolData2", boolData2)
                    .expire(expire) // use expire
                    .build();
            list.add(jwt);
        }

        // create jwt by mirror
        for (int i = 0 ; i < 10 ; i++) {
            String jwt = mirrorServer.createJwt().issuer(issuer)
                    .subject(subject)
                    .audience(audience)
                    .id(id)
                    .claim("boolData", boolData)
                    .claim("boolData2", boolData2)
                    .build();
            list.add(jwt);
        }

        Assertions.assertEquals(20, list.size());
        System.out.println("create " + list.size() + " jwts");

        // parse jwt by provider
        for (String jwt : list) {
            JwtNode node = providerServer.parseJwt(jwt);
            Assertions.assertEquals(issuer, node.getIssuer());
            Assertions.assertEquals(subject, node.getSubject());
            Assertions.assertEquals(audience, node.getAudience());
            Assertions.assertEquals(id, node.getId());
            Assertions.assertEquals(boolData, node.claimBoolean("boolData"));
            Assertions.assertEquals(false, node.claimBoolean("boolData2"));
        }
        System.out.println("parse jwts by provider");

        // parse jwt by mirror
        for (String jwt : list) {
            JwtNode node = mirrorServer.parseJwt(jwt);
            Assertions.assertEquals(issuer, node.getIssuer());
            Assertions.assertEquals(subject, node.getSubject());
            Assertions.assertEquals(audience, node.getAudience());
            Assertions.assertEquals(id, node.getId());
            Assertions.assertEquals(boolData, node.claimBoolean("boolData"));
            Assertions.assertEquals(false, node.claimBoolean("boolData2"));
        }
        System.out.println("parse jwts by mirror");
        System.out.println(providerServer.getState());
        System.out.println(mirrorServer.getState());
    }
}
