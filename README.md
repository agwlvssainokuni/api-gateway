# API Gateway
Spring Cloud Gatewayを利用したAPI Gatewayの実装例。

# 準備
## KeyCloakを起動する
```
cd keycloak
docker compose up -d
```

## KeyCloakを初期設定する
### ログイン
* [KeyCloak(http://localhost:8080/auth/)](http://localhost:8080/auth/) を開く。
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
* KeyCloakからログアウトする。


# 実行
## API Gatewayを起動する
```
./gradlew clean bootRun
```

## アクセストークンを発行する
```
clientid=cloudgateway
clientsecret={KeyCloakの画面で確認したクライアントシークレット}
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
< Date: Sun, 24 Jul 2022 11:33:54 GMT
< Content-Type: application/json
< Server: gunicorn/19.9.0
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< content-length: 560
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
    "Forwarded": "proto=http;host=\"localhost:8090\";for=\"[0:0:0:0:0:0:0:1]:55092\"", 
    "Host": "httpbin.org", 
    "User-Agent": "curl/7.64.1", 
    "X-Amzn-Trace-Id": "Root=1-62dd2e22-5c0047d1559ff93d3d42f847", 
    "X-Forwarded-Host": "localhost:8090", 
    "X-Forwarded-Prefix": "/pubapi"
  }, 
  "json": null, 
  "method": "GET", 
  "origin": "0:0:0:0:0:0:0:1, 227.227.227.227", 
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
< Date: Sun, 24 Jul 2022 11:34:51 GMT
< Content-Type: application/json
< Server: gunicorn/19.9.0
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< content-length: 618
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
    "Forwarded": "proto=http;host=\"localhost:8090\";for=\"[0:0:0:0:0:0:0:1]:55099\"", 
    "Host": "httpbin.org", 
    "User-Agent": "curl/7.64.1", 
    "X-Amzn-Trace-Id": "Root=1-62dd2e5b-06349e5c28bc8ee87a85a609", 
    "X-Forwarded-Host": "localhost:8090", 
    "X-Forwarded-Prefix": "/pubapi", 
    "X-Jwt-Sub": "b16d2eb5-901c-4d80-ae1e-2ea99f9df931"
  }, 
  "json": null, 
  "method": "GET", 
  "origin": "0:0:0:0:0:0:0:1, 227.227.227.227", 
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
< Date: Sun, 24 Jul 2022 11:36:11 GMT
< Content-Type: application/json
< Server: gunicorn/19.9.0
< Access-Control-Allow-Origin: *
< Access-Control-Allow-Credentials: true
< content-length: 618
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
    "Forwarded": "proto=http;host=\"localhost:8090\";for=\"[0:0:0:0:0:0:0:1]:55107\"", 
    "Host": "httpbin.org", 
    "User-Agent": "curl/7.64.1", 
    "X-Amzn-Trace-Id": "Root=1-62dd2eab-4f34983617912c9a795d2a6f", 
    "X-Forwarded-Host": "localhost:8090", 
    "X-Forwarded-Prefix": "/prvapi", 
    "X-Jwt-Sub": "b16d2eb5-901c-4d80-ae1e-2ea99f9df931"
  }, 
  "json": null, 
  "method": "GET", 
  "origin": "0:0:0:0:0:0:0:1, 227.227.227.227", 
  "url": "http://localhost:8090/anything"
}
* Connection #0 to host localhost left intact
* Closing connection 0
```

# 補足
## ゲートウェイのアクセスログ
* システムプロパティ `-Dreactor.netty.http.server.accessLogEnabled=true` を設定して起動すると Spring Cloud Gatewayのアクセスログが出力される。

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
