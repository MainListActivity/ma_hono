CREATE UNIQUE INDEX oidc_clients_tenant_db_client_unique
ON oidc_clients (tenant_id)
WHERE client_profile = 'db';
