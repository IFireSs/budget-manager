# JWT-контракт

## Тип токена

- Тип токена: JWT access token
- Алгоритм подписи: `RS256`
- Issuer по умолчанию: `auth-service`
- Глобальный максимум TTL по умолчанию: `PT10M`
- Передача токена: `Authorization: Bearer <access-token>`
- Публичные ключи: `GET /.well-known/jwks.json`

Issuer, audience auth-service и глобальный максимум TTL настраиваются через переменные окружения:

```env
APP_SECURITY_ACCESS_TOKEN_ISSUER=auth-service
APP_SECURITY_ACCESS_TOKEN_AUDIENCE=auth-service
APP_SECURITY_ACCESS_TOKEN_TTL=PT10M
```

Фактический TTL access token равен меньшему значению из `APP_SECURITY_ACCESS_TOKEN_TTL` и
`auth_clients.access_token_ttl_seconds` для client application.

Ключи подписи задаются так:

```env
APP_SECURITY_JWT_PRIVATE_KEY=<base64-pkcs8-private-key>
APP_SECURITY_JWT_PUBLIC_KEY=<base64-x509-public-key>
APP_SECURITY_JWT_KEY_ID=auth-service-key-1
```

Auth-service хранит private key и подписывает им access tokens. Resource-сервисы используют public key из JWKS endpoint и могут только проверять токены, но не выпускать их.

## Header

Auth-service формирует JWS header:

```json
{
  "alg": "RS256",
  "kid": "auth-service-key-1"
}
```

Значение header-полей:

- `alg`: алгоритм подписи токена.
- `kid`: идентификатор ключа подписи. Значение берётся из `APP_SECURITY_JWT_KEY_ID` и позволяет сопоставить токен с public key из JWKS.

## Claims

Auth-service выпускает access token с такими claims:

```json
{
  "iss": "auth-service",
  "sub": "username",
  "aud": ["auth-service"],
  "iat": 1710000000,
  "exp": 1710000600,
  "uid": "7bfae473-a56d-4a64-8f3f-2159e73e4f3a",
  "roles": ["USER"],
  "sid": "0f5df3f8-21d9-42f9-8d55-1df1dc030301",
  "client_id": "auth-service"
}
```

Значение claims:

- `iss`: issuer токена. Resource-сервисы обязаны его валидировать.
- `sub`: username аутентифицированного пользователя.
- `aud`: список audience токена. Он содержит audience auth-service из `APP_SECURITY_ACCESS_TOKEN_AUDIENCE` и audience client application из `auth_clients.token_audience`. Для стандартного frontend-клиента `auth-service` оба значения совпадают, поэтому в токене остается один `aud`.
- `uid`: стабильный UUID пользователя в auth-service. Resource-сервисы должны использовать его как внешний user id.
- `roles`: роли пользователя без префикса `ROLE_`. Spring resource server должен мапить их в authorities с префиксом `ROLE_`.
- `sid`: id login-сессии в auth-service. Resource-сервисы не должны использовать его как id пользователя.
- `client_id`: id client application из `auth_clients.client_id`. Auth-service использует claim для проверки активного клиента, stateful validation и origin binding.
- `iat`: время выпуска токена.
- `exp`: время истечения токена.

## Правила валидации

Resource-сервисы должны валидировать:

- подпись JWT через public key/JWKS;
- `iss` равен ожидаемому issuer;
- `aud` содержит ожидаемую audience resource-сервиса;
- `exp` ещё не истёк;
- обязательные claims присутствуют: `sub`, `aud`, `uid`, `roles`, `sid`, `client_id`;
- типы claims соответствуют контракту: `uid` является строкой в формате UUID, `roles` является массивом строк, `sid` и `client_id` являются строками.

Resource-сервисы должны хранить `uid` как UUID/UUID-строку и не преобразовывать его в числовой тип.

Resource-сервисы могут игнорировать `sid`, если им не нужна session-level диагностика. Они не должны обращаться напрямую к таблицам БД auth-service.

Auth-service при приёме access token дополнительно проверяет, что `aud` содержит
`APP_SECURITY_ACCESS_TOKEN_AUDIENCE`. Проверка audience должна проверять наличие ожидаемого
значения в списке, а не точное равенство всего списка.

## Семантика logout и блокировки пользователя

Auth-service проверяет активный бан при login, refresh и при валидации каждого bearer JWT для собственных endpoint'ов.
В stateful-режиме он дополнительно проверяет активность auth-client'а и наличие активной refresh-сессии
по `uid + client_id + sid`.

Внешние resource-сервисы должны валидировать access token stateless:

- logout сразу отзывает refresh/session state в auth-service;
- бан пользователя сразу отзывает все его refresh-сессии и запрещает login/refresh;
- уже выпущенные access tokens остаются валидными в resource-сервисах до `exp`;
- короткий TTL access token ограничивает максимальную задержку.

Если понадобится мгновенный logout или бан во всех сервисах, нужно добавить API gateway со stateful validation,
introspection endpoint или доставку revocation events. Resource-сервисы не должны напрямую читать таблицы auth-service.
