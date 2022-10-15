# API Gateway
[Spring Cloud Gateway](https://spring.io/projects/spring-cloud-gateway) を利用した API Gateway の実装例。

## 概要
* API Gateway のポート番号は `8090`。
* 実APIは [httpbin.org](http://httpbin.org/) をコンテナ起動。ポート番号は `8081`。
* 認証プロバイダとして [Keycloak](https://www.keycloak.org/) をコンテナ起動。ポート番号は `8080`。
* API呼出し時の認可処理 (JWT検証) を Spring Security の「[OAuth2 Resource Server](https://docs.spring.io/spring-security/reference/reactive/oauth2/resource-server/index.html)]」の機能により実装する。
* アクセストークン(JWT)に格納されるクレーム値をHTTPリクエストヘッダとして実APIへ受け渡す。


## API Gatewayの構成のポイント
### 認証プロバイダ設定
```
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8080/auth/realms/mydemo
```

### 実APIへのルーティング設定
```
spring.cloud.gateway.routes[0].id=prvapi
spring.cloud.gateway.routes[0].uri=http://localhost:8081/
spring.cloud.gateway.routes[0].predicates[0]=Path=/prvapi/**
spring.cloud.gateway.routes[0].filters[0]=StripPrefix=1
spring.cloud.gateway.routes[0].filters[1]=RemoveRequestHeader=Authorization
spring.cloud.gateway.routes[0].filters[2]=AddRequestHeaderFromJwt=X-JWT-SUB, sub

spring.cloud.gateway.routes[1].id=pubapi
spring.cloud.gateway.routes[1].uri=http://localhost:8081/
spring.cloud.gateway.routes[1].predicates[0]=Path=/pubapi/**
spring.cloud.gateway.routes[1].filters[0]=StripPrefix=1
spring.cloud.gateway.routes[1].filters[1]=RemoveRequestHeader=Authorization
spring.cloud.gateway.routes[1].filters[2]=AddRequestHeaderFromJwt=X-JWT-SUB, sub
```

### クレーム値を実APIへ受け渡す `GatewayFilterFactory`
```Java
return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
        // JWTクレームを取得する。
        .map(SecurityContext::getAuthentication).map(Authentication::getPrincipal)
        .filter(Jwt.class::isInstance).map(Jwt.class::cast)
        .map(jwt -> jwt.getClaimAsString(config.getClaim()))
        // JWTクレームをリクエストヘッダへ設定する。
        .flatMap(claim -> Mono.just(exchange).map(ServerWebExchange::getRequest)
                .map(ServerHttpRequest::mutate)
                .map(req -> req.header(config.getHeader(), claim))
                .map(ServerHttpRequest.Builder::build))
        // リクエストを更新する。
        .flatMap(req -> Mono.just(exchange)
                .map(ServerWebExchange::mutate)
                .map(exchg -> exchg.request(req))
                .map(ServerWebExchange.Builder::build))
        // JWTクレームが存在しない場合はリクエストを更新しない。
        .switchIfEmpty(Mono.just(exchange))
        // フィルタ処理を進める。
        .flatMap(chain::filter);
```


# 準備
## 動作確認用コンテナ(Keycloak, httpbin.org)を起動する
```
cd server
docker compose up -d
```

## Keycloakを初期設定する
### ログイン
* [Keycloak(http://localhost:8080/auth/)](http://localhost:8080/auth/) を開く。
* 管理コンソール (Administration Console) のリンクをクリックする。
* ログインする。(`admin/password`)

### レルム
* レルム `mydemo` を作成する。
  * [OpenID Connect Discovery](http://localhost:8080/auth/realms/mydemo/.well-known/openid-configuration)

### クライアント
* クライアント `cloudgateway` を作成する。
  * Client Protocol: `openid-connect`
  * Root URL: `http://localhost:8090/`
* クライアント `cloudgateway` を設定変更する。
  * Access Type: `confidential`
* クライアント `cloudgateway` のクライアントシークレットを確認する。(あとで使う)

### ユーザ
* ユーザ `user001` を作成する。
* ユーザ `user001` にパスワードを設定する。

### ログアウト
* Keycloakからログアウトする。

## 動作確認用コンテナ(Keycloak, httpbin.org)を停止する
```
cd server
docker compose down
```


# 実行
## 動作確認用コンテナ(Keycloak, httpbin.org)を起動する
```
cd server
docker compose up -d
```

## API Gatewayを起動する
```
./gradlew clean bootRun
```

## アクセストークンを発行する
```
clientid=cloudgateway
clientsecret={Keycloakの画面で確認したクライアントシークレット}
username=user001
password={user001のパスワード}

json=$(curl http://localhost:8080/auth/realms/mydemo/protocol/openid-connect/token \
        --data username=${username} \
        --data password=${password} \
        --data grant_type=password \
        -H "Authorization: Basic $(echo -n ${clientid}:${clientsecret} \
        | base64)")

token=$(echo "${json}" | jq --raw-output .access_token)

echo "${json}"
echo "${token}"
```

## 公開APIへリクエストを発行する
### アクセストークン指定なし
```
curl -v http://localhost:8090/pubapi/anything
```

#### 結果例
```
$ curl -v http://localhost:8090/pubapi/anything
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8090 (#0)
> GET /pubapi/anything HTTP/1.1
> Host: localhost:8090
> User-Agent: curl/7.64.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Vary: Origin
< Vary: Access-Control-Request-Method
< Vary: Access-Control-Request-Headers
< Server: gunicorn/19.9.0
< Date: Sun, 24 Jul 2022 13:13:45 GMT
< Content-Type: application/json
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< content-length: 479
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Content-Type-Options: nosniff
< X-Frame-Options: DENY
< X-XSS-Protection: 1 ; mode=block
< Referrer-Policy: no-referrer
< 
{
  "args": {}, 
  "data": "", 
  "files": {}, 
  "form": {}, 
  "headers": {
    "Accept": "*/*", 
    "Content-Length": "0", 
    "Forwarded": "proto=http;host=\"localhost:8090\";for=\"[0:0:0:0:0:0:0:1]:55777\"", 
    "Host": "localhost:8081", 
    "User-Agent": "curl/7.64.1", 
    "X-Forwarded-Host": "localhost:8090", 
    "X-Forwarded-Prefix": "/pubapi"
  }, 
  "json": null, 
  "method": "GET", 
  "origin": "0:0:0:0:0:0:0:1", 
  "url": "http://localhost:8090/anything"
}
* Connection #0 to host localhost left intact
* Closing connection 0
```

### アクセストークン指定あり
```
curl -v http://localhost:8090/pubapi/anything -H "Authorization: Bearer ${token}"
```
* APIの公開/認証要判定の前にJWT検証が実行される。このため、公開APIであっても不適切なJWT(形式不正とか期限切れとか)が指定されると、`401 Unauthorized` になるので注意。

#### 結果例
```
$ curl -v http://localhost:8090/pubapi/anything -H "Authorization: Bearer ${token}"
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8090 (#0)
> GET /pubapi/anything HTTP/1.1
> Host: localhost:8090
> User-Agent: curl/7.64.1
> Accept: */*
> Authorization: Bearer {略}
> 
< HTTP/1.1 200 OK
< Vary: Origin
< Vary: Access-Control-Request-Method
< Vary: Access-Control-Request-Headers
< Server: gunicorn/19.9.0
< Date: Sun, 24 Jul 2022 13:14:52 GMT
< Content-Type: application/json
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< content-length: 537
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Content-Type-Options: nosniff
< X-Frame-Options: DENY
< X-XSS-Protection: 1 ; mode=block
< Referrer-Policy: no-referrer
< 
{
  "args": {}, 
  "data": "", 
  "files": {}, 
  "form": {}, 
  "headers": {
    "Accept": "*/*", 
    "Content-Length": "0", 
    "Forwarded": "proto=http;host=\"localhost:8090\";for=\"[0:0:0:0:0:0:0:1]:55803\"", 
    "Host": "localhost:8081", 
    "User-Agent": "curl/7.64.1", 
    "X-Forwarded-Host": "localhost:8090", 
    "X-Forwarded-Prefix": "/pubapi", 
    "X-Jwt-Sub": "b16d2eb5-901c-4d80-ae1e-2ea99f9df931"
  }, 
  "json": null, 
  "method": "GET", 
  "origin": "0:0:0:0:0:0:0:1", 
  "url": "http://localhost:8090/anything"
}
* Connection #0 to host localhost left intact
* Closing connection 0
```

## 認証要APIへリクエストを発行する
### アクセストークン指定なし
```
curl -v http://localhost:8090/prvapi/anything
```

#### 結果例
```
$ curl -v http://localhost:8090/prvapi/anything
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8090 (#0)
> GET /prvapi/anything HTTP/1.1
> Host: localhost:8090
> User-Agent: curl/7.64.1
> Accept: */*
> 
< HTTP/1.1 401 Unauthorized
< Vary: Origin
< Vary: Access-Control-Request-Method
< Vary: Access-Control-Request-Headers
< WWW-Authenticate: Bearer
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Content-Type-Options: nosniff
< X-Frame-Options: DENY
< X-XSS-Protection: 1 ; mode=block
< Referrer-Policy: no-referrer
< content-length: 0
< 
* Connection #0 to host localhost left intact
* Closing connection 0
```

### アクセストークン指定あり
```
curl -v http://localhost:8090/prvapi/anything -H "Authorization: Bearer ${token}"
```

#### 結果例
```
$ curl -v http://localhost:8090/prvapi/anything -H "Authorization: Bearer ${token}"
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 8090 (#0)
> GET /prvapi/anything HTTP/1.1
> Host: localhost:8090
> User-Agent: curl/7.64.1
> Accept: */*
> Authorization: Bearer {略}
> 
< HTTP/1.1 200 OK
< Vary: Origin
< Vary: Access-Control-Request-Method
< Vary: Access-Control-Request-Headers
< Server: gunicorn/19.9.0
< Date: Sun, 24 Jul 2022 13:16:20 GMT
< Content-Type: application/json
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< content-length: 537
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Content-Type-Options: nosniff
< X-Frame-Options: DENY
< X-XSS-Protection: 1 ; mode=block
< Referrer-Policy: no-referrer
< 
{
  "args": {}, 
  "data": "", 
  "files": {}, 
  "form": {}, 
  "headers": {
    "Accept": "*/*", 
    "Content-Length": "0", 
    "Forwarded": "proto=http;host=\"localhost:8090\";for=\"[0:0:0:0:0:0:0:1]:55813\"", 
    "Host": "localhost:8081", 
    "User-Agent": "curl/7.64.1", 
    "X-Forwarded-Host": "localhost:8090", 
    "X-Forwarded-Prefix": "/prvapi", 
    "X-Jwt-Sub": "b16d2eb5-901c-4d80-ae1e-2ea99f9df931"
  }, 
  "json": null, 
  "method": "GET", 
  "origin": "0:0:0:0:0:0:0:1", 
  "url": "http://localhost:8090/anything"
}
* Connection #0 to host localhost left intact
* Closing connection 0
```

## 動作確認用コンテナ(Keycloak, httpbin.org)を停止する
```
cd server
docker compose down
```


# 補足
## API Gatewayのアクセスログ
* システムプロパティ `-Dreactor.netty.http.server.accessLogEnabled=true` を設定して起動すると Spring Cloud Gatewayのアクセスログが出力される。([Spring Cloud Gateway - 13. Reactor Netty Access Logs](https://docs.spring.io/spring-cloud-gateway/docs/current/reference/html/#reactor-netty-access-logs))

```
./gradlew clean build
java -Dreactor.netty.http.server.accessLogEnabled=true -jar build/libs/api-gateway.jar
```
#### 出力例
```
2022-07-24-21:11:59.285 INFO  [reactor-http-nio-2] reactor.netty.http.server.AccessLog - 0:0:0:0:0:0:0:1 - - [24/7月/2022:21:11:57 +0900] "GET /pubapi/anything HTTP/1.1" 200 560 1418
2022-07-24-21:12:16.029 INFO  [reactor-http-nio-1] reactor.netty.http.server.AccessLog - 0:0:0:0:0:0:0:1 - - [24/7月/2022:21:12:14 +0900] "GET /pubapi/anything HTTP/1.1" 200 618 1504
2022-07-24-21:12:24.513 INFO  [reactor-http-nio-4] reactor.netty.http.server.AccessLog - 0:0:0:0:0:0:0:1 - - [24/7月/2022:21:12:24 +0900] "GET /prvapi/anything HTTP/1.1" 401 0 18
2022-07-24-21:12:31.823 INFO  [reactor-http-nio-1] reactor.netty.http.server.AccessLog - 0:0:0:0:0:0:0:1 - - [24/7月/2022:21:12:31 +0900] "GET /prvapi/anything HTTP/1.1" 200 618 664
```
