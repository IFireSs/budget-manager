# auth-service

Spring Boot сервис аутентификации и авторизации.

Сервис отвечает за регистрацию пользователей, login/password authentication, выпуск JWT access tokens, хранение и rotation refresh tokens, logout, управление ролями, admin API, audit events, Kafka outbox и rate limiting чувствительных endpoint'ов.

## Стек

- Java 21
- Spring Boot 3.5
- Spring Security
- Spring Data JPA
- PostgreSQL
- Flyway
- Redis
- Kafka
- Docker Compose
- Testcontainers
- Springdoc OpenAPI

## Возможности

- Регистрация пользователей.
- Login по username/password.
- JWT access token с RSA-подписью.
- Refresh token в HttpOnly cookie.
- Rotation refresh token при каждом refresh.
- Reuse detection для refresh token.
- Logout одной сессии, всех сессий и конкретной сессии.
- Stateful validation access token внутри auth-service.
- Постоянные и временные блокировки пользователей с историей и отзывом всех сессий.
- Admin API для пользователей, блокировок, ролей, сессий, audit events и auth clients.
- JWKS endpoint для resource-сервисов.
- Audit events с transactional outbox.
- Опциональная публикация audit events в Kafka.
- Redis-backed rate limit для горизонтального масштабирования.
- Защита login от brute force и password spraying через три bucket'а: `LOGIN_IP`, `LOGIN_ACCOUNT` и `LOGIN_ACCOUNT_IP`.

## Структура

```text
src/main/java/com/project/auth_service
|-- api                 REST controllers
|-- api/dto             request/response DTO
|-- config              security, JWT, CORS, OpenAPI, properties
|-- cookie              auth cookie factories
|-- entity              JPA entities
|-- enums               roles, statuses, audit event types
|-- exception_handler   global exception handling
|-- exceptions          domain exceptions
|-- jobs                scheduled jobs
|-- rate_limit          rate limit filter and backends
|-- repository          Spring Data repositories
`-- service             business logic
```

## Требования

- JDK 21
- Docker
- PowerShell или другой shell
- Для локального запуска без Docker: PostgreSQL, Redis и Kafka по необходимости

## Быстрый запуск через Docker Compose

1. Создать `.env` из примера:

```powershell
Copy-Item .env.example .env
```

2. Заполнить JWT keys и секреты в `.env`.

Минимально нужно заменить:

```env
APP_SECURITY_JWT_PRIVATE_KEY=...
APP_SECURITY_JWT_PUBLIC_KEY=...
APP_SECURITY_REFRESH_REPLAY_SECRET=...
```

3. Собрать и запустить сервисы:

```powershell
docker compose up --build
```


4. Проверить readiness:

```powershell
Invoke-RestMethod http://localhost:8080/actuator/health/readiness
```

Ожидаемый ответ:

```json
{
  "status": "UP"
}
```

## Генерация JWT RSA ключей

Приложение принимает RSA private key в формате PKCS#8 и public key в формате X.509. Значения можно передавать как чистый Base64 или PEM-like строку.

PowerShell пример:

```powershell
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$privateKey = [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey())
$publicKey = [Convert]::ToBase64String($rsa.ExportSubjectPublicKeyInfo())

"APP_SECURITY_JWT_PRIVATE_KEY=$privateKey"
"APP_SECURITY_JWT_PUBLIC_KEY=$publicKey"
```

Скопировать полученные значения в `.env`.

## Основные сервисы Docker Compose

- `auth-service` - Spring Boot приложение на `http://localhost:8080`.
- `auth-postgres` - PostgreSQL на `localhost:5432`.
- `redis` - Redis на `localhost:6379`.
- `kafka` - Kafka broker на `localhost:9092`.
- `kafka-ui` - Kafka UI на `http://localhost:8085`.

## Локальный запуск через Maven

1. Поднять инфраструктуру:

```powershell
docker compose up -d auth-postgres redis kafka
```

2. Убедиться, что `.env` заполнен.

3. Запустить приложение:

```powershell
.\mvnw.cmd spring-boot:run
```

По умолчанию локальный `.env.example` использует:

```env
APP_RATE_LIMIT_BACKEND=in-memory
APP_EVENTS_KAFKA_ENABLED=false
```

Для Redis-backed rate limit при локальном запуске:

```env
APP_RATE_LIMIT_BACKEND=redis
APP_RATE_LIMIT_REDIS_HEALTH_ENABLED=true
REDIS_HOST=localhost
REDIS_PORT=6379
```

## Тесты

Запуск полного набора тестов:

```powershell
.\mvnw.cmd test
```

Тесты используют Testcontainers для PostgreSQL и Redis backend проверки.

## Основные endpoint'ы

Auth API:

```http
GET  /api/v1/auth/csrf
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
POST /api/v1/auth/logout-all
POST /api/v1/auth/logout-session/{sessionId}
POST /api/v1/auth/password/change
GET  /api/v1/auth/sessions
```

Admin API:

```http
GET    /api/v1/admin/users
GET    /api/v1/admin/users/{userId}
GET    /api/v1/admin/users/{userId}/sessions
GET    /api/v1/admin/audit-events
GET    /api/v1/admin/auth-clients
POST   /api/v1/admin/auth-clients
PUT    /api/v1/admin/auth-clients/{clientId}
POST   /api/v1/admin/auth-clients/{clientId}/enable
POST   /api/v1/admin/auth-clients/{clientId}/disable
POST   /api/v1/admin/users/{userId}/logout-all
POST   /api/v1/admin/users/{userId}/sessions/{sessionId}/revoke
PUT    /api/v1/admin/users/{userId}/ban
DELETE /api/v1/admin/users/{userId}/ban
PUT    /api/v1/admin/users/{userId}/roles/admin
DELETE /api/v1/admin/users/{userId}/roles/admin
```

Public/system endpoints:

```http
GET /.well-known/jwks.json
GET /actuator/health
GET /actuator/health/readiness
GET /actuator/health/liveness
GET /swagger-ui/index.html
GET /v3/api-docs
```

## Идентификаторы пользователей

- Пользовательские идентификаторы имеют тип UUID в PostgreSQL и Java.
- JWT claim `uid`, параметры admin API и audit-события передают UUID как строку.
- Для порядка пользователей UI должен использовать `createdAt`, а не значение UUID.
- Переход исторической схемы с `BIGINT` на UUID выполняет Flyway-миграция `V11__migrate_user_ids_to_uuid.sql`.

## CSRF flow для Postman и frontend

Cookie-auth endpoint'ы требуют CSRF:

```http
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
```

Перед запросом:

1. Выполнить:

```http
GET /api/v1/auth/csrf
```

2. Взять `token` из JSON body.

3. Сохранить cookie `XSRF-TOKEN`.

4. В POST-запросах передавать header:

```http
X-XSRF-TOKEN: <token>
```

5. Передавать cookie:

```http
XSRF-TOKEN=<cookie-value>
```

После успешного login/register сервис вернет access token в JSON body и выставит cookies:

```text
refresh_token
session_id
```

## Rate limit

Настройки:

```env
APP_RATE_LIMIT_BACKEND=in-memory
APP_RATE_LIMIT_BACKEND=redis
APP_RATE_LIMIT_LOGIN_ACCOUNT_KEY_SECRET=change-me-to-a-long-random-rate-limit-account-key-secret
APP_RATE_LIMIT_LOGIN_IP_CAPACITY=30
APP_RATE_LIMIT_LOGIN_IP_REFILL_PERIOD=PT10M
APP_RATE_LIMIT_LOGIN_ACCOUNT_CAPACITY=10
APP_RATE_LIMIT_LOGIN_ACCOUNT_REFILL_PERIOD=PT15M
APP_RATE_LIMIT_LOGIN_ACCOUNT_IP_CAPACITY=5
APP_RATE_LIMIT_LOGIN_ACCOUNT_IP_REFILL_PERIOD=PT10M
APP_RATE_LIMIT_REGISTER_CAPACITY=10
APP_RATE_LIMIT_REGISTER_REFILL_PERIOD=PT10M
APP_RATE_LIMIT_REFRESH_CAPACITY=30
APP_RATE_LIMIT_REFRESH_REFILL_PERIOD=PT1M
APP_RATE_LIMIT_PASSWORD_CHANGE_CAPACITY=5
APP_RATE_LIMIT_PASSWORD_CHANGE_REFILL_PERIOD=PT10M
APP_RATE_LIMIT_ADMIN_CAPACITY=60
APP_RATE_LIMIT_ADMIN_REFILL_PERIOD=PT1M
APP_RATE_LIMIT_REDIS_KEY_PREFIX=auth-service:rate-limit
APP_RATE_LIMIT_TRUSTED_PROXIES=10.0.0.0/8
APP_RATE_LIMIT_AUDIT_GLOBAL_CAPACITY=100
APP_RATE_LIMIT_AUDIT_GLOBAL_WINDOW=PT1M
APP_RATE_LIMIT_AUDIT_PER_KEY_INTERVAL=PT5M
```

В Docker Compose используется Redis backend:

```env
APP_RATE_LIMIT_BACKEND=redis
REDIS_HOST=redis
```

Login защищен тремя bucket'ами:

- `LOGIN_IP` - общий лимит на IP.
- `LOGIN_ACCOUNT` - общий лимит на нормализованный account identifier независимо от IP.
- `LOGIN_ACCOUNT_IP` - лимит на связку account identifier и IP.

Account identifier хранится в ключах rate limit только как HMAC-SHA-256. Секрет
`APP_RATE_LIMIT_LOGIN_ACCOUNT_KEY_SECRET` должен быть одинаковым на всех экземплярах
приложения и содержать не менее 32 символов. Его ротация сбрасывает account-based bucket'ы.

Это значит, что разные account identifier с одного IP упрутся в `LOGIN_IP`, а попытки подобрать
пароль одного account identifier с разных IP - в `LOGIN_ACCOUNT`. Redis backend использует Lua
script, чтобы атомарно проверить все три bucket'а и не допустить partial consume.

`X-Forwarded-For` учитывается только когда непосредственный `remoteAddr` входит в
`APP_RATE_LIMIT_TRUSTED_PROXIES`. Цепочка разбирается справа налево до первого
недоверенного адреса. Невалидная или слишком длинная цепочка игнорируется.

Каждый отклоненный запрос учитывается метрикой `auth.rate_limit.rejected`.
Audit-события `RATE_LIMIT_EXCEEDED` дополнительно ограничиваются локально:
не чаще одного события на `scope + IP` за `APP_RATE_LIMIT_AUDIT_PER_KEY_INTERVAL`
и не более `APP_RATE_LIMIT_AUDIT_GLOBAL_CAPACITY` событий за скользящее
`APP_RATE_LIMIT_AUDIT_GLOBAL_WINDOW`.

Проверить Redis-ключи:

```powershell
docker exec auth-redis redis-cli keys "auth-service:rate-limit*"
docker exec auth-redis redis-cli hgetall "auth-service:rate-limit:login:ip:<ip>"
```

## Kafka outbox

Audit events сохраняются в БД всегда. Публикация в Kafka включается настройкой:

```env
APP_EVENTS_KAFKA_ENABLED=true
APP_EVENTS_KAFKA_BATCH_SIZE=50
APP_EVENTS_KAFKA_PUBLISHER_FIXED_DELAY_MS=5000
APP_EVENTS_KAFKA_RETRY_DELAY_MS=30000
APP_EVENTS_KAFKA_LEASE_DURATION_MS=300000
APP_EVENTS_KAFKA_SEND_TIMEOUT_MS=5000
APP_EVENTS_KAFKA_MAX_ATTEMPTS=10
```

В Docker Compose публикация включена, broker доступен как `kafka:9092`.

При claim событие получает уникальный `claim_id`, lease и увеличенный `attempts`. Завершить
публикацию может только worker с актуальным `claim_id`. После исчерпания `max-attempts`
событие переходит в `DEAD` и больше автоматически не публикуется. Доставка остается
at-least-once, поэтому consumer должен дедуплицировать события по `id`.

Lease должен быть длиннее максимального времени последовательной обработки batch:

```text
APP_EVENTS_KAFKA_LEASE_DURATION_MS >
APP_EVENTS_KAFKA_BATCH_SIZE * APP_EVENTS_KAFKA_SEND_TIMEOUT_MS
```

Приложение валидирует это условие при старте. Локально в `.env.example` публикация отключена:

```env
APP_EVENTS_KAFKA_ENABLED=false
```

## Bootstrap SUPER_ADMIN

Первого super-admin можно создать при старте:

```env
APP_BOOTSTRAP_SUPERADMIN_ENABLED=true
APP_BOOTSTRAP_SUPERADMIN_REQUIRE_EMPTY_USER_STORE=true
APP_BOOTSTRAP_SUPERADMIN_USERNAME=admin
APP_BOOTSTRAP_SUPERADMIN_EMAIL=admin@example.com
APP_BOOTSTRAP_SUPERADMIN_PASSWORD=change-me
```

После первого успешного запуска лучше отключить bootstrap:

```env
APP_BOOTSTRAP_SUPERADMIN_ENABLED=false
```

Bootstrap `SUPER_ADMIN` помечается как защищенный от блокировки. Это постоянный признак пользователя,
поэтому он сохраняется после отключения bootstrap.

## Важные переменные окружения

База данных:

```env
DB_URL=jdbc:postgresql://localhost:5432/authdb
DB_USERNAME=bd...
DB_PASSWORD=bd...
```

JWT:

```env
APP_SECURITY_JWT_PRIVATE_KEY=...
APP_SECURITY_JWT_PUBLIC_KEY=...
APP_SECURITY_JWT_KEY_ID=auth-service-key-1
APP_SECURITY_ACCESS_TOKEN_ISSUER=auth-service
APP_SECURITY_ACCESS_TOKEN_AUDIENCE=auth-service
APP_SECURITY_ACCESS_TOKEN_TTL=PT10M
APP_SECURITY_ACCESS_TOKEN_VALIDATION_MODE=stateful
```

Cookies:

```env
APP_SECURITY_COOKIES_SECURE=false
APP_SECURITY_COOKIES_SAME_SITE=Lax
```

Refresh tokens:

```env
APP_SECURITY_REFRESH_TTL=P14D
APP_SECURITY_REFRESH_REUSE_GRACE=PT3S
APP_SECURITY_REFRESH_REPLAY_SECRET=change-me-to-a-long-random-refresh-replay-secret
APP_SECURITY_REFRESH_REQUIRE_SESSION_ID=true
APP_SECURITY_REFRESH_BIND_TO_USER_AGENT=true
APP_SECURITY_REFRESH_BIND_TO_IP=false
APP_SECURITY_REFRESH_CLEANUP_ENABLED=true
APP_SECURITY_REFRESH_CLEANUP_RETENTION=P7D
APP_SECURITY_REFRESH_CLEANUP_CRON=0 0 4 * * *
APP_SECURITY_REFRESH_REPLAY_PAYLOAD_CLEANUP_FIXED_DELAY_MS=5000
```

`APP_SECURITY_REFRESH_REUSE_GRACE` задает короткое окно идемпотентности refresh rotation. После его окончания сервис очищает зашифрованный replay payload (`rotation_result_token_cipher` и связанные поля), но оставляет revoked refresh-token row для reuse detection.

## OpenAPI

Swagger UI:

```text
http://localhost:8080/swagger-ui/index.html
```

OpenAPI JSON:

```text
http://localhost:8080/v3/api-docs
```

Статический контракт также лежит в:

```text
docs/openapi.yaml
```

## Документация

- `docs/jwt-contract.md` - контракт JWT для resource-сервисов.
- `docs/resource-server-integration.md` - интеграция resource-сервисов.
- `docs/admin-permissions.md` - модель admin permissions.

## Типичные команды

Пересобрать и запустить:

```powershell
docker compose up --build
```

Перезапустить только auth-service после изменений:

```powershell
docker compose up --build -d auth-service
```

Посмотреть логи:

```powershell
docker logs auth-service
```

Остановить окружение:

```powershell
docker compose down
```

Остановить окружение и удалить volumes:

```powershell
docker compose down -v
```
