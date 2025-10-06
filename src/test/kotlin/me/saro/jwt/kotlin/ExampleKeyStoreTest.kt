package me.saro.jwt.kotlin

import me.saro.jwt.old.Jwt
import me.saro.jwt.old.exception.JwtException
import me.saro.jwt.old.store.JwtKeyStoreMirror
import me.saro.jwt.old.store.JwtKeyStoreProvider
import org.junit.jupiter.api.*
import java.time.Duration
import java.time.OffsetDateTime

@DisplayName("[kotlin] key store example test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(
    MethodOrderer.DisplayName::class
)
class ExampleKeyStoreTest {
    private var providerServer: JwtKeyStoreProvider? = null
    private var mirrorServer: JwtKeyStoreMirror? = null
    private var database = ""

    @Test
    @DisplayName("[kotlin] 01 create provider server")
    fun test01() {
        // provider server
        // jwt: create [OK] paser [OK]
        // key: issue [OK] export [OK] import [only in builder]

        // jwt provider server
        // create and export keys

        providerServer = Jwt.createKeyStoreProvider()
            .algorithm(Jwt.ES512) // expire time default 0, 0 is never expire
            .keyExpireTime(Duration.ofHours(3)) // provider and mirror sync time (default 0)
            // - before sync time, the key can only be parseJwt() not createJwt()
            .keySyncTime(Duration.ofSeconds(5))
            .build()
        println("create provider server")

        val providerServer = this.providerServer!!

        // make 3 keys
        providerServer.issue()
        providerServer.issue()
        Thread.sleep(1000) // test for delay 1 second
        providerServer.issue()
        Assertions.assertEquals(3, providerServer.getAllKeysForMonitor().size)
        println("issue 3 keys:${providerServer.getAllKeysForMonitor()}")
        Assertions.assertEquals(3, providerServer.getNotReadyKeysForMonitor().size)
        println(providerServer.getState())

        // export to database
        database = providerServer.exports()
        println("export to database\n$database")
    }

    @Test
    @DisplayName("[kotlin] 02 create mirror server")
    fun test02() {
        if (providerServer == null) {
            test01()
        }

        // mirror server
        // jwt: create [OK] paser [OK]
        // key: issue [NO] export [OK] import [OK]

        // jwt mirror server
        // create and import keys
        mirrorServer = Jwt.createKeyStoreMirror()
            .imports(database)
            .build()
        println("create mirror server")

        val mirrorServer = this.mirrorServer!!

        // exports, imports test
        val exports = mirrorServer.exports()
        Assertions.assertEquals(database, exports)
        mirrorServer.imports(exports)
        Assertions.assertEquals(exports, mirrorServer.exports())
        Assertions.assertEquals(3, mirrorServer.getAllKeysForMonitor().size)
        println("exports, imports test\n$exports")
        Assertions.assertEquals(3, mirrorServer.getNotReadyKeysForMonitor().size)
        println(mirrorServer.getState())
    }

    @Test
    @DisplayName("[kotlin] 03 jwt ready test (mixed provider and mirror)")
    fun test03() {
        if (mirrorServer == null) {
            test02()
        }

        val providerServer = this.providerServer!!
        val mirrorServer = this.mirrorServer!!

        // provider server
        // jwt: create [OK] paser [OK]
        // key: issue [OK] export [OK] import [only in builder]

        // mirror server
        // jwt: create [OK] paser [OK]
        // key: issue [NO] export [OK] import [OK]


        // cannot create, only parse (before sync time)
        Assertions.assertThrows(
            JwtException::class.java
        ) { providerServer.createJwt().build() }
        Assertions.assertThrows(
            JwtException::class.java
        ) { mirrorServer.createJwt().build() }

        // wait for key sync time -> .keySyncTime(Duration.ofSeconds(5))
        Thread.sleep(5000)

        // ready
        Assertions.assertDoesNotThrow<String> { providerServer.createJwt().build() }
        Assertions.assertDoesNotThrow<String> { mirrorServer.createJwt().build() }
    }

    @Test
    @DisplayName("[kotlin] 04 jwt (create / parse) test (mixed provider and mirror)")
    fun test04() {
        if (mirrorServer == null) {
            test03()
        }

        val providerServer = this.providerServer!!
        val mirrorServer = this.mirrorServer!!

        // jwts list
        val list: MutableList<String> = ArrayList()

        // test data
        val issuer = "issuer1"
        val subject = "subject2"
        val audience = "audience3"
        val id = "id4"
        val boolData = true
        val boolData2 = "no"
        val expire = OffsetDateTime.now().plusHours(1).toEpochSecond()

        // create jwt by provider
        for (i in 0..9) {
            val jwt = providerServer.createJwt().issuer(issuer)
                .subject(subject)
                .audience(audience)
                .id(id)
                .claim("boolData", boolData)
                .claim("boolData2", boolData2)
                .expire(expire) // use expire
                .build()
            list.add(jwt)
        }

        // create jwt by mirror
        for (i in 0..9) {
            val jwt = mirrorServer.createJwt().issuer(issuer)
                .subject(subject)
                .audience(audience)
                .id(id)
                .claim("boolData", boolData)
                .claim("boolData2", boolData2)
                .build()
            list.add(jwt)
        }

        Assertions.assertEquals(20, list.size)
        println("create " + list.size + " jwts")

        // parse jwt by provider
        for (jwt in list) {
            val node = providerServer.parseJwt(jwt)
            Assertions.assertEquals(issuer, node.issuer)
            Assertions.assertEquals(subject, node.subject)
            Assertions.assertEquals(audience, node.audience)
            Assertions.assertEquals(id, node.id)
            Assertions.assertEquals(boolData, node.claimBoolean("boolData"))
            Assertions.assertEquals(false, node.claimBoolean("boolData2"))
        }
        println("parse jwts by provider")

        // parse jwt by mirror
        for (jwt in list) {
            val node = mirrorServer.parseJwt(jwt)
            Assertions.assertEquals(issuer, node.issuer)
            Assertions.assertEquals(subject, node.subject)
            Assertions.assertEquals(audience, node.audience)
            Assertions.assertEquals(id, node.id)
            Assertions.assertEquals(boolData, node.claimBoolean("boolData"))
            Assertions.assertEquals(false, node.claimBoolean("boolData2"))
        }
        println("parse jwts by mirror")
        println(providerServer.getState())
        println(mirrorServer.getState())
    }
}
