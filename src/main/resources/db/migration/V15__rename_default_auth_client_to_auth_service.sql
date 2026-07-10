INSERT INTO auth_clients (
    client_id,
    name,
    enabled,
    access_token_ttl_seconds,
    refresh_token_ttl_seconds,
    token_audience,
    allowed_origins,
    created_at,
    updated_at
)
SELECT
    'auth-service',
    'Auth Service UI',
    enabled,
    access_token_ttl_seconds,
    refresh_token_ttl_seconds,
    'auth-service',
    allowed_origins,
    created_at,
    now()
FROM auth_clients
WHERE client_id = 'budget-manager-web'
ON CONFLICT (client_id) DO UPDATE
SET name = EXCLUDED.name,
    enabled = EXCLUDED.enabled,
    access_token_ttl_seconds = EXCLUDED.access_token_ttl_seconds,
    refresh_token_ttl_seconds = EXCLUDED.refresh_token_ttl_seconds,
    token_audience = EXCLUDED.token_audience,
    allowed_origins = EXCLUDED.allowed_origins,
    updated_at = now();

UPDATE refresh_tokens
SET client_id = 'auth-service'
WHERE client_id = 'budget-manager-web';

DELETE FROM auth_clients
WHERE client_id = 'budget-manager-web';
