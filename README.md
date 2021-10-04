### SARO JWT
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/me.saro/jwt/badge.svg)](https://maven-badges.herokuapp.com/maven-central/me.saro/jwt)
[![GitHub license](https://img.shields.io/github/license/saro-lab/jwt.svg)](https://github.com/saro-lab/jwt/blob/master/LICENSE)

# QUICK START

## gradle kts
```
implementation('me.saro:jwt:0.11.2.2')
```

## gradle
```
compile 'me.saro:jwt:0.11.2.2'
```

## maven
``` xml
<dependency>
  <groupId>me.saro</groupId>
  <artifactId>jwt</artifactId>
  <version>0.11.2.2</version>
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
    .encryptClaim("jti", "1234")
    .subject("sub")
    .issuer("iss")
    .issuedAtNow()
    .expireMinutes(30)
    .build();

System.out.println("jwt: " + jwt);

String header = new String(Base64.getDecoder().decode(jwt.split("\\.")[0]));
System.out.println("header: " + header);

String payload = new String(Base64.getDecoder().decode(jwt.split("\\.")[1]));
System.out.println("payload: " + payload);

JwtReader jwtReader = jwtKeyManager.parse(jwt);

Map<String, Object> result = new HashMap<>();
result.put("id", jwtReader.decryptClaim("jti"));
result.put("subject", jwtReader.getSubject());
result.put("issuer", jwtReader.getIssuer());
result.put("issuedAt", jwtReader.getIssuedAt());
result.put("expire", jwtReader.getExpire());
System.out.println("result: " + result);
```
### example result
```
jwt: eyJraWQiOiI1YjlhZTEwMi01NmVlLTRiMDItODJlZC01OWE4NzBiZTQ4MWEiLCJhbGciOiJSUzI1NiJ9.eyJqdGkiOiJhM2Q5THR1YUlJSGRFY2Jjcm13eGJBcjRIcTZ4ZFdoeEhFNXZoYlB2azBFTU1KYk9PaFdxK290TENQUDIzK2NNdXNBR0pIU0grMmhPOVJHTFBCdmkzcFRmRGpRQnRERVZ1THlqOG1HMDBXTllvUldLL3EwSzJ3MzNHY3g4RUl0Z0M5bU80NXlxWWFyeXVBRVBnYi92SWNXODZIaG03ajJ5ckkrNTIzaHpaRHkxeGtrZ3lnSmg3TWdnbWo4aXp3ZFczQlF1YzBrZEk2aVhXcVAxejh4b0RVUHdiZUJwMGxtc29rSkwvMW9KSitjQXhjVnN5YUZtWFZTUWlEK0JlVmlaYWRreC9lMUxLT1BqOG1sZnJMS3EzU3pHRTdRdlhRdURIQzRMN0lzVXV3RnRKZnNnL083T1RoVW4zcURtN21KWk81dEpaSFNWQ3NtSkNrYnJVQnJYNFE9PSIsInN1YiI6InN1YiIsImlzcyI6ImlzcyIsImlhdCI6MTYzMzMxMzg1NSwiZXhwIjoxNjMzMzE1NjU1fQ.CdG54XBrGV2E6FILS8PhcdLCXWoOYVcrbClaXCiam-gXYzUZE3_HFfPiT_uD2zHy2IPftJvQlp1I5jR22TiDxik9S35ypMc3I40C2IkCSn-lC7y6jsKDdSuPsyOIARasvlPz53orBknamVMCj26XwO-1EpY1hbmM3yGqzIdOGElmua-xsMqlfGADPkpCxR3-w-acE5814L7ZIU7JJPtsZwRD9CaFSlKwwr2JjOss_QcD2DaLGU--8u5BtmTihqbjezFjhVjGnQssk_QP_4zFkO7H9NrmXISKcBT-BTECCI8MdftidPCdjQK1zfuvwPPHJXix0s65t6tmvJnhR-D1Mw
header: {"kid":"5b9ae102-56ee-4b02-82ed-59a870be481a","alg":"RS256"}
payload: {"jti":"a3d9LtuaIIHdEcbcrmwxbAr4Hq6xdWhxHE5vhbPvk0EMMJbOOhWq+otLCPP23+cMusAGJHSH+2hO9RGLPBvi3pTfDjQBtDEVuLyj8mG00WNYoRWK/q0K2w33Gcx8EItgC9mO45yqYaryuAEPgb/vIcW86Hhm7j2yrI+523hzZDy1xkkgygJh7Mggmj8izwdW3BQuc0kdI6iXWqP1z8xoDUPwbeBp0lmsokJL/1oJJ+cAxcVsyaFmXVSQiD+BeViZadkx/e1LKOPj8mlfrLKq3SzGE7QvXQuDHC4L7IsUuwFtJfsg/O7OThUn3qDm7mJZO5tJZHSVCsmJCkbrUBrX4Q==","sub":"sub","iss":"iss","iat":1633313855,"exp":1633315655}
result: {subject=sub, expire=Mon Oct 04 11:47:35 KST 2021, id=1234, issuedAt=Mon Oct 04 11:17:35 KST 2021, issuer=iss}
```

## Kotlin
- [MainTest.kt](https://github.com/saro-lab/jwt/blob/main/src/test/kotlin/me/saro/jwt/kotlin/MainTest.kt)
  - example
```
// algorithm: RS256, key rotation queue size: 3, key rotation minutes: 30
// key stored [rotation minutes (30) * queue size (3)] = 90 minutes
val jwtKeyManager: JwtKeyManager = create(SignatureAlgorithm.RS256, 3, 30)

val jwt = jwtKeyManager.getJwtBuilder()
    .encryptClaim("jti", "1234")
    .subject("sub")
    .issuer("iss")
    .issuedAtNow()
    .expireMinutes(30)
    .build()
println("jwt: $jwt")

val header = String(Base64.getDecoder().decode(jwt.split(".")[0]))
println("header: $header")

val payload = String(Base64.getDecoder().decode(jwt.split(".")[1]))
println("payload: $payload")

val jwtReader = jwtKeyManager.parse(jwt)

val result = mapOf(
    "id" to jwtReader.decryptClaim("jti"),
    "subject" to jwtReader.subject,
    "issuer" to jwtReader.issuer,
    "issuedAt" to jwtReader.issuedAt,
    "expire" to jwtReader.expire
)
println("result: $result")
```
### result
```
jwt: eyJraWQiOiI0YzFiMDE4ZC1mMTFkLTQ1MjYtOGY2Yi1iYjJmYjM4Y2Q1ZTgiLCJhbGciOiJSUzI1NiJ9.eyJqdGkiOiI0SmoxUVd1cWFyUDRrZmprRHUvQkJQNUlXZWxZS1VxV2tyUlRGUHV4dFFXUWd5TjBpbWN2amN3Mng3RUl1U0FDQzExUS9kYXpCMFBJN1QzdnVQZnVCL2ZLUDZLTFBZTEwzL3E0V2IxVzJCcUNlaUlNaDNJb0JDVzZZeGxQaHh1VFhZUmQ4UWJERzhMQmNEWXF0STFRL2NOanh4bm9GZkFJSS9zbTd5amUweGpGV3p0Wkh2elZtUGtZUWdtNzdoOVhYODZ5amJUZUt6V0ozTzRKVml5NitlZnczN3E3V0RXWlFDdVp1dG4vY085VVMwMzBsdkFUSjJseFM3cmZSNTZ6ZlZhRnFsRlBJZnBEK0dHZU9rQ1B2WXFMUFhrQkZpY2w3Zk1DT1RmazVLY0owRThQL2lMbFoxa1hBRk5tN3R2aWtOME1yRW5IVHRPRjhGV0pmWmJhWXc9PSIsInN1YiI6InN1YiIsImlzcyI6ImlzcyIsImlhdCI6MTYzMzMxMzk0MCwiZXhwIjoxNjMzMzE1NzQwfQ.37D99kblPuPa6vIKiYrTwnL2FpeAduF4byo6XjF405LwNeucm9i9QMldI7wHVF47VZ7qakJgUKCPEArUB8PVsHj6yMTcohI-GmrkXPpToJWTYJ1hbqNxFuJbudGh9gTjj95xjHBtFLwjU6wIRu1G8MMJsi6CZWBvNYeuZB5KN-EzXhgpMIfrU0wFvcDnkqNLEv0TFmCtA7OVmwYLJhCE7rPWFZ6gyaKBUwFxsW_0JUmjg37pjHgIwGG-HkM9dmRf6lGRAXpKFHdvDuGGNNzwUCMKkF69SEM3KHIADzsm3bwgyta3VM27KjM9O6bNMCaCdg83HjhRpi0pvnOcFVhRgg
header: {"kid":"4c1b018d-f11d-4526-8f6b-bb2fb38cd5e8","alg":"RS256"}
payload: {"jti":"4Jj1QWuqarP4kfjkDu/BBP5IWelYKUqWkrRTFPuxtQWQgyN0imcvjcw2x7EIuSACC11Q/dazB0PI7T3vuPfuB/fKP6KLPYLL3/q4Wb1W2BqCeiIMh3IoBCW6YxlPhxuTXYRd8QbDG8LBcDYqtI1Q/cNjxxnoFfAII/sm7yje0xjFWztZHvzVmPkYQgm77h9XX86yjbTeKzWJ3O4JViy6+efw37q7WDWZQCuZutn/cO9US030lvATJ2lxS7rfR56zfVaFqlFPIfpD+GGeOkCPvYqLPXkBFicl7fMCOTfk5KcJ0E8P/iLlZ1kXAFNm7tvikN0MrEnHTtOF8FWJfZbaYw==","sub":"sub","iss":"iss","iat":1633313940,"exp":1633315740}
result: {subject=sub, expire=Mon Oct 04 11:49:00 KST 2021, id=1234, issuedAt=Mon Oct 04 11:19:00 KST 2021, issuer=iss}
```

## repository
- https://search.maven.org/artifact/me.saro/jwt
- https://mvnrepository.com/artifact/me.saro/jwt

## see
- [가리사니 개발자공간](https://gs.saro.me)

## include
- [io.jsonwebtoken:jjwt](https://github.com/jwtk/jjwt)
