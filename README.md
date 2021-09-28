### SARO JWT
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/me.saro/jwt/badge.svg)](https://maven-badges.herokuapp.com/maven-central/me.saro/jwt)
[![GitHub license](https://img.shields.io/github/license/saro-lab/jwt.svg)](https://github.com/saro-lab/jwt/blob/master/LICENSE)

# QUICK START

## gradle kts
```
implementation('me.saro:jwt:0.11.2.1')
```

## gradle
```
compile 'me.saro:jwt:0.11.2.1'
```

## maven
``` xml
<dependency>
  <groupId>me.saro</groupId>
  <artifactId>jwt</artifactId>
  <version>0.11.2.1</version>
</dependency>
```

## Java
- [MainTest.java](https://github.com/saro-lab/jwt/blob/main/src/test/java/me/saro/jwt/java/MainTest.java)
    - example
```
// algorithm: RS256, key rotation queue size: 3, key rotation minutes: 30
// key stored [rotation minutes (30) * queue size (3)] = 90 minutes
JwtKeyManager jwtKeyManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 3, 30);

String jwt = jwtKeyManager.getJwtBuilder()
    .encryptClaim(ClaimName.id, "1234")
    .claim(ClaimName.subject, "sub")
    .claim(ClaimName.issuer, "iss")
    .setIssuedAtNow()
    .setExpireMinutes(30)
    .build();

System.out.println("jwt: " + jwt);

String header = new String(Base64.getDecoder().decode(jwt.split("\\.")[0]));
System.out.println("header: " + header);

String payload = new String(Base64.getDecoder().decode(jwt.split("\\.")[1]));
System.out.println("payload: " + payload);

JwtReader jwtReader = jwtKeyManager.parse(jwt);

Map<String, String> result = new HashMap<>();
result.put("id", jwtReader.decryptClaim(ClaimName.id));
result.put("subject", jwtReader.claim(ClaimName.subject).toString());
result.put("issuer", jwtReader.claim(ClaimName.issuer).toString());
result.put("issuedAt", jwtReader.claim("iat").toString());
result.put("expire", jwtReader.claim("exp").toString());
System.out.println("result: " + result);
```
### example result
```
jwt: eyJraWQiOiIzNzI2YTZmYS01NGYwLTRiNzktODAyMS03ZjVlZTAwODQzNjAiLCJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJmL2hWbURJY1VXYUNoZVVJS0pnRXZkeHZMVUgrY3ZNeG5NV3BTTlpWR3VFdmIvcytjQ2VYQ010cFpJSnEyQkdMeFhLNy9wbHAvZlAzSTZmaXBNWFJIVFUvTWVxZkNFajVwcVVYSGNNdG1tQ1l6MlJ4QXhmVStXSG1DUXZEb09DT3ZOZkhHUy9qLzlzSnZJVnB0bTRuaGl2emROTlR2cUVHL2FtRXB6NnhtV0FwNXJ4WHcyN0c4a0c1MTBseHVkR2VRNVpVd1dxL2ZTeXEzcCt2VUcyRzI2SWNlREdncEF5QVFkUnFVRUJGUEZ0aXRqaWZTVGdKdmw1a2VVY2F1Y012WnJERHRxZUg5VWxrUXFRUmwxbG01Ryt5eXIyZDFWQ1dwSEZIWWs0OGhzTmJrZDNZZ2FMK1pCT0tPZHVQTGJzemduZmRGL1h0TmNCdENxUkNadHZpRlE9PSIsInN1YiI6InN1YiIsImlzcyI6ImlzcyIsImlhdCI6MTYzMjg1NjY0MCwiZXhwIjoxNjMyODU4NDQwfQ.A0zjgTnlsPSbZgejGMoytV5XGclIsx66iFxXnrAwCqJr_l00POT1PnTobbPLGy9xStGFsF7NaNt7AYvnPNp3G_lBMJ9kfPGWjBGdQ1JM-xeNQp5YzBwUMryJvzXiS7xOV0KIu7vZe-xGiCqibK7kPF4rvl0kXCcRRkCCHJbyC3Z1kTdCNbIuQ3KIHfcbS3ReLplw8QwtHUg9TPOCjW47u1MIqsrRN9OUVGq3ooxE2TQsJ7htz_vCPcd_qEV7oHc-Q-Kh-2R8mVdyY5L2KfOg5BI57MTsiz6F0cGETk9nc8RPIRO8aoxiIgVRgz9sQgCvQFw73E6GOqSzqq7jsXJdcQ
header: {"kid":"3726a6fa-54f0-4b79-8021-7f5ee0084360","alg":"RS256"}
payload: {"jti":"f/hVmDIcUWaCheUIKJgEvdxvLUH+cvMxnMWpSNZVGuEvb/s+cCeXCMtpZIJq2BGLxXK7/plp/fP3I6fipMXRHTU/MeqfCEj5pqUXHcMtmmCYz2RxAxfU+WHmCQvDoOCOvNfHGS/j/9sJvIVptm4nhivzdNNTvqEG/amEpz6xmWAp5rxXw27G8kG510lxudGeQ5ZUwWq/fSyq3p+vUG2G26IceDGgpAyAQdRqUEBFPFtitjifSTgJvl5keUcaucMvZrDDtqeH9UlkQqQRl1lm5G+yyr2d1VCWpHFHYk48hsNbkd3YgaL+ZBOKOduPLbszgnfdF/XtNcBtCqRCZtviFQ==","sub":"sub","iss":"iss","iat":1632856640,"exp":1632858440}
result: {subject=sub, expire=1632858440, id=1234, issuedAt=1632856640, issuer=iss}
```

## Kotlin
- [MainTest.kt](https://github.com/saro-lab/jwt/blob/main/src/test/kotlin/me/saro/jwt/kotlin/MainTest.kt)
  - example
```
// algorithm: RS256, key rotation queue size: 3, key rotation minutes: 30
// key stored [rotation minutes (30) * queue size (3)] = 90 minutes
val jwtKeyManager: JwtKeyManager = create(SignatureAlgorithm.RS256, 3, 30)

val jwt = jwtKeyManager.getJwtBuilder()
    .encryptClaim(ClaimName.id, "1234")
    .claim(ClaimName.subject, "sub")
    .claim(ClaimName.issuer, "iss")
    .setIssuedAtNow()
    .setExpireMinutes(30)
    .build()
println("jwt: $jwt")

val header = String(Base64.getDecoder().decode(jwt.split(".")[0]))
println("header: $header")

val payload = String(Base64.getDecoder().decode(jwt.split(".")[1]))
println("payload: $payload")

val jwtReader = jwtKeyManager.parse(jwt)

val result = mapOf(
    "id" to jwtReader.decryptClaim(ClaimName.id),
    "subject" to jwtReader.claim(ClaimName.subject),
    "issuer" to jwtReader.claim(ClaimName.issuer),
    "issuedAt" to jwtReader.claim("iat"),
    "expire" to jwtReader.claim("exp")
)
println("result: $result")
```
### result
```
jwt: eyJraWQiOiJkNjk2YzIwZS0yYWNmLTQ4ZWMtODk0ZS03NTRkYzZiYzkxOTUiLCJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJJMDRZOWZXV1h1a2tOc2VRVm92TGlMaWRFUG5ESkh3Qk16RFdrSExZUHJNNEZGUm9uT3UvMjFtODBkcDZTeUliQVRmaXBwb0NXVzh1RCtUa3QyMG5aLzU5elF4MnRxWC8rN2RQWXpQNkEyYm1kYnZuQmxYSWtjeCtPTnQzK2hkV3lFc3B6dWNxOWNTdm14OENUckgxSlQ5eVpPbU03anE2dmgrV0tlQjRFbXNKSkdhZlN3b3lyNVJBTUQzMGNFQk5hZm1qWGc3Y0tYcVZsTDNYajlCQkFQaUVnaHdXcVc5QTlUMGp6YUdCcERyalgxV3FBeE9CQ2RaMWw3MDg4YmIyNGxjOC81K0RKQVVsZ2NhWmZCVnMzdlJ0bzRsUWRuZUJtZ1dhZ0x5Sm0xZmptUEJlY2Y5UmwyOExXMHJYMWM1RVhPVUt0eURySjJhcC9jU2dLK1VJMHc9PSIsInN1YiI6InN1YiIsImlzcyI6ImlzcyIsImlhdCI6MTYzMjg1NjcxNSwiZXhwIjoxNjMyODU4NTE1fQ.gIcpTHGvRy2TFQKoCFlcI82xf3SDL-LZPT7BZcam8dVcYVfcTWKh1_kdSjA-O0UY4sbjT1kYvKtUK12iQH6jFjnebOIWcA42t1Z5M1-8ztJt3hNAnjOOg5iLeT0P1rD-0fPS4NLL8m8QE34p-O0EFDUxIP4eYnQaXZrrGfT6ZF1mT-p3TMHZD9C8QNm5A0S9V90RePzj5Dn7KfN6dkrELkddFqjIjKZMYOYgZANg7NqDh01XcIDjT-kkdxpukhCkCL0iWSv_Ek-Igx-jth7G4iHQe_E5U_Us3oJjxoh1tZvhMY6CIvu07jASRhYRBeZX6oyAEQFkZDoHfUx4Coyuaw
header: {"kid":"d696c20e-2acf-48ec-894e-754dc6bc9195","alg":"RS256"}
payload: {"jti":"I04Y9fWWXukkNseQVovLiLidEPnDJHwBMzDWkHLYPrM4FFRonOu/21m80dp6SyIbATfippoCWW8uD+Tkt20nZ/59zQx2tqX/+7dPYzP6A2bmdbvnBlXIkcx+ONt3+hdWyEspzucq9cSvmx8CTrH1JT9yZOmM7jq6vh+WKeB4EmsJJGafSwoyr5RAMD30cEBNafmjXg7cKXqVlL3Xj9BBAPiEghwWqW9A9T0jzaGBpDrjX1WqAxOBCdZ1l7088bb24lc8/5+DJAUlgcaZfBVs3vRto4lQdneBmgWagLyJm1fjmPBecf9Rl28LW0rX1c5EXOUKtyDrJ2ap/cSgK+UI0w==","sub":"sub","iss":"iss","iat":1632856715,"exp":1632858515}
result: {id=1234, subject=sub, issuer=iss, issuedAt=1632856715, expire=1632858515}
```

## repository
- https://search.maven.org/artifact/me.saro/jwt
- https://mvnrepository.com/artifact/me.saro/jwt

## see
- [가리사니 개발자공간](https://gs.saro.me)

## include
- [io.jsonwebtoken:jjwt](https://github.com/jwtk/jjwt)
