//! Postgres access. Every operation uses BEGIN, SET LOCAL, DEALLOCATE ALL and timeouts.

use {
    chrono::{DateTime, Utc},
    deadpool_postgres::{
        Client, Config, ManagerConfig, Pool, PoolConfig, RecyclingMethod, Runtime,
    },
    openssl::ssl::{SslConnector, SslMethod},
    postgres_openssl::MakeTlsConnector,
    serde_json::Value,
    std::time::Duration,
    tokio::time::timeout,
    tokio_postgres::{types::ToSql, Row},
    tracing::warn,
    uuid::Uuid,
};

use crate::error::Error;

#[derive(Clone, Debug)]
pub struct ServiceRow {
    pub service_id: String,
    pub merchant_wallet: String,
    pub service_url: String,
    pub resources_allowlist: Value,
    pub pack_bundles: Option<Value>,
    pub status: String,
}

#[derive(Clone, Debug)]
pub struct MarketplaceRow {
    pub service_id: String,
    pub merchant_wallet: String,
    pub service_url: String,
    pub resources_allowlist: Value,
    pub pack_bundles: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct InsertServiceParams<'a> {
    pub service_id: &'a str,
    pub merchant_wallet: &'a str,
    pub service_url: &'a str,
    pub resources_allowlist: &'a Value,
    pub pack_bundles: Option<&'a Value>,
    pub category: Option<&'a str>,
    pub tags: &'a Value,
}

#[derive(Clone, Debug)]
pub struct PackRow {
    pub jti: Uuid,
    pub service_id: String,
    pub payer: String,
    pub pack_id: String,
    pub total_uses: i64,
    pub used_uses: i64,
    pub resources: Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct ConsumptionResult {
    pub consumption_id: Uuid,
    pub remaining_uses: i64,
    pub consumed_at: DateTime<Utc>,
    pub replayed: bool,
}

#[derive(Clone, Debug)]
pub enum ConsumeOutcome {
    Consumed(ConsumptionResult),
    NotFound,
    Revoked,
    Expired,
    Exhausted,
    IdempotencyConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeNonceOutcome {
    Inserted,
    RateLimited,
}

#[derive(Clone)]
pub struct AuthDb {
    pool: Pool,
}

impl AuthDb {
    const POOL_TIMEOUT: Duration = Duration::from_secs(20);
    const WIRE_TIMEOUT: Duration = Duration::from_secs(25);

    pub fn connect(database_url: String) -> Result<Self, Error> {
        let mut config = Config::new();
        config.url = Some(database_url);
        config.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        config.pool = Some(PoolConfig {
            max_size: 5,
            ..Default::default()
        });
        let mut ssl = SslConnector::builder(SslMethod::tls())
            .map_err(|error| Error::Internal(error.to_string()))?;
        if env_flag("PACK_AUTH_SSL_NO_VERIFY") {
            ssl.set_verify(openssl::ssl::SslVerifyMode::NONE);
            warn!("PACK_AUTH_SSL_NO_VERIFY enabled; do not use in production");
        } else {
            ssl.set_verify(openssl::ssl::SslVerifyMode::PEER);
        }
        let pool = config
            .create_pool(Some(Runtime::Tokio1), MakeTlsConnector::new(ssl.build()))
            .map_err(|error| Error::Internal(format!("database pool: {error}")))?;
        Ok(Self { pool })
    }

    pub fn from_env_var(name: &str) -> Option<Result<Self, Error>> {
        std::env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .map(Self::connect)
    }

    async fn conn(&self) -> Result<Client, Error> {
        timeout(Self::POOL_TIMEOUT, self.pool.get())
            .await
            .map_err(|_| Error::Internal("database pool checkout timed out".into()))?
            .map_err(|error| Error::Internal(format!("database pool: {error}")))
    }

    pub async fn ping(&self) -> Result<(), Error> {
        let client = self.conn().await?;
        timeout(Duration::from_secs(8), client.simple_query("SELECT 1"))
            .await
            .map_err(|_| Error::Internal("database ping timed out".into()))?
            .map_err(|error| Error::Internal(format!("database ping: {error}")))?;
        Ok(())
    }

    pub async fn insert_challenge_nonce(
        &self,
        wallet: &str,
        nonce: &str,
        expires_at: DateTime<Utc>,
        max_nonces: i64,
    ) -> Result<ChallengeNonceOutcome, Error> {
        let row = self
            .query_opt(
                r#"WITH counted AS (
                   SELECT COUNT(*) AS n FROM pack_auth_nonces
                   WHERE wallet=$1 AND expires_at > NOW()
               )
               INSERT INTO pack_auth_nonces(wallet, nonce, expires_at)
               SELECT $1, $2, $3 WHERE (SELECT n FROM counted) < $4
               ON CONFLICT DO NOTHING RETURNING 1"#,
                &[&wallet, &nonce, &expires_at, &max_nonces],
                "insert challenge nonce",
            )
            .await?;
        Ok(if row.is_some() {
            ChallengeNonceOutcome::Inserted
        } else {
            ChallengeNonceOutcome::RateLimited
        })
    }

    pub async fn consume_nonce(&self, wallet: &str, nonce: &str) -> Result<bool, Error> {
        Ok(self
            .execute(
                "DELETE FROM pack_auth_nonces WHERE wallet=$1 AND nonce=$2 AND expires_at > NOW()",
                &[&wallet, &nonce],
                "consume nonce",
            )
            .await?
            > 0)
    }

    pub async fn cleanup_expired_nonces(&self) -> Result<u64, Error> {
        self.execute(
            "DELETE FROM pack_auth_nonces WHERE expires_at < NOW() - INTERVAL '1 hour'",
            &[],
            "cleanup nonces",
        )
        .await
    }

    pub async fn get_service(&self, service_id: &str) -> Result<Option<ServiceRow>, Error> {
        Ok(self.query_opt(
            "SELECT service_id, merchant_wallet, service_url, resources_allowlist, pack_bundles, status FROM pack_auth_services WHERE service_id=$1",
            &[&service_id], "get service"
        ).await?.map(service_from_row))
    }

    pub async fn insert_service(&self, params: InsertServiceParams<'_>) -> Result<(), Error> {
        self.execute(
            "INSERT INTO pack_auth_services(service_id, merchant_wallet, service_url, resources_allowlist, pack_bundles, category, tags) VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[&params.service_id, &params.merchant_wallet, &params.service_url, &params.resources_allowlist, &params.pack_bundles, &params.category, &params.tags], "insert service"
        ).await?;
        Ok(())
    }

    pub async fn update_service(
        &self,
        service_id: &str,
        merchant_wallet: &str,
        allowlist: &Value,
        bundles: Option<&Value>,
        category: Option<&str>,
        tags: Option<&Value>,
    ) -> Result<bool, Error> {
        let rows = if let (Some(category), Some(tags)) = (category, tags) {
            self.execute("UPDATE pack_auth_services SET resources_allowlist=$3, pack_bundles=$4, category=$5, tags=$6, updated_at=NOW() WHERE service_id=$1 AND merchant_wallet=$2 AND status='active'", &[&service_id, &merchant_wallet, &allowlist, &bundles, &category, &tags], "update service").await?
        } else {
            self.execute("UPDATE pack_auth_services SET resources_allowlist=$3, updated_at=NOW() WHERE service_id=$1 AND merchant_wallet=$2 AND status='active'", &[&service_id, &merchant_wallet, &allowlist], "update service").await?
        };
        Ok(rows > 0)
    }

    pub async fn retire_service(
        &self,
        service_id: &str,
        merchant_wallet: &str,
    ) -> Result<bool, Error> {
        Ok(self.execute("UPDATE pack_auth_services SET status='retired', updated_at=NOW() WHERE service_id=$1 AND merchant_wallet=$2 AND status='active'", &[&service_id, &merchant_wallet], "retire service").await? > 0)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_pack(
        &self,
        jti: Uuid,
        service_id: &str,
        payer: &str,
        pack_id: &str,
        total_uses: i64,
        resources: &Value,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), Error> {
        self.execute(
            "INSERT INTO pack_auth_packs(jti, service_id, payer, pack_id, total_uses, resources, issued_at, expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&jti, &service_id, &payer, &pack_id, &total_uses, &resources, &issued_at, &expires_at], "insert pack"
        ).await?;
        Ok(())
    }

    pub async fn get_pack(&self, jti: Uuid) -> Result<Option<PackRow>, Error> {
        Ok(self.query_opt(
            "SELECT jti, service_id, payer, pack_id, total_uses, used_uses, resources, issued_at, expires_at, revoked_at FROM pack_auth_packs WHERE jti=$1",
            &[&jti], "get pack"
        ).await?.map(pack_from_row))
    }

    pub async fn revoke_pack(
        &self,
        jti: Uuid,
        service_id: &str,
        merchant_wallet: &str,
    ) -> Result<bool, Error> {
        Ok(self.execute(
            "UPDATE pack_auth_packs p SET revoked_at=NOW() FROM pack_auth_services s WHERE p.jti=$1 AND p.service_id=$2 AND s.service_id=p.service_id AND s.merchant_wallet=$3 AND p.revoked_at IS NULL",
            &[&jti, &service_id, &merchant_wallet], "revoke pack"
        ).await? > 0)
    }

    /// Atomically records an idempotency key and consumes exactly one use.
    pub async fn consume_pack(
        &self,
        jti: Uuid,
        idempotency_key: &str,
        resource: &str,
    ) -> Result<ConsumeOutcome, Error> {
        let client = self.conn().await?;
        if let Err(error) = open_transaction(&client, "consume pack").await {
            discard(client);
            return Err(error);
        }
        let result = self
            .consume_pack_in_open_tx(&client, jti, idempotency_key, resource)
            .await;
        match result {
            Ok(outcome) => {
                if let Err(error) = commit(&client, "consume pack").await {
                    discard(client);
                    return Err(error);
                }
                Ok(outcome)
            }
            Err(error) => {
                rollback(&client, "consume pack").await;
                discard(client);
                Err(error)
            }
        }
    }

    async fn consume_pack_in_open_tx(
        &self,
        client: &Client,
        jti: Uuid,
        key: &str,
        resource: &str,
    ) -> Result<ConsumeOutcome, Error> {
        let pack = wire(client.query_opt(
            "SELECT revoked_at, expires_at, total_uses, used_uses FROM pack_auth_packs WHERE jti=$1 FOR UPDATE",
            &[&jti],
        ), "lock pack").await?;
        let Some(pack) = pack else {
            return Ok(ConsumeOutcome::NotFound);
        };

        if let Some(existing) = wire(client.query_opt(
            "SELECT consumption_id, resource, remaining_after, consumed_at FROM pack_auth_consumptions WHERE jti=$1 AND idempotency_key=$2",
            &[&jti, &key],
        ), "find consumption").await? {
            if existing.get::<_, String>("resource") != resource {
                return Ok(ConsumeOutcome::IdempotencyConflict);
            }
            return Ok(ConsumeOutcome::Consumed(ConsumptionResult {
                consumption_id: existing.get("consumption_id"),
                remaining_uses: existing.get("remaining_after"),
                consumed_at: existing.get("consumed_at"),
                replayed: true,
            }));
        }

        if pack.get::<_, Option<DateTime<Utc>>>("revoked_at").is_some() {
            return Ok(ConsumeOutcome::Revoked);
        }
        if pack.get::<_, DateTime<Utc>>("expires_at") <= Utc::now() {
            return Ok(ConsumeOutcome::Expired);
        }
        let total = pack.get::<_, i64>("total_uses");
        let used = pack.get::<_, i64>("used_uses");
        if used >= total {
            return Ok(ConsumeOutcome::Exhausted);
        }

        let remaining = total - used - 1;
        let consumption_id = Uuid::new_v4();
        let row = wire(client.query_one(
            "INSERT INTO pack_auth_consumptions(consumption_id, jti, idempotency_key, resource, remaining_after) VALUES($1,$2,$3,$4,$5) RETURNING consumed_at",
            &[&consumption_id, &jti, &key, &resource, &remaining],
        ), "insert consumption").await?;
        wire(
            client.execute(
                "UPDATE pack_auth_packs SET used_uses=used_uses+1 WHERE jti=$1",
                &[&jti],
            ),
            "increment used uses",
        )
        .await?;
        Ok(ConsumeOutcome::Consumed(ConsumptionResult {
            consumption_id,
            remaining_uses: remaining,
            consumed_at: row.get("consumed_at"),
            replayed: false,
        }))
    }

    pub async fn list_packs(
        &self,
        merchant_wallet: &str,
        service_id: Option<&str>,
        limit: i64,
        before: Option<DateTime<Utc>>,
    ) -> Result<(Vec<PackRow>, bool), Error> {
        let fetch = limit + 1;
        let rows = self
            .query(
                r#"SELECT p.jti, p.service_id, p.payer, p.pack_id, p.total_uses, p.used_uses,
                      p.resources, p.issued_at, p.expires_at, p.revoked_at
               FROM pack_auth_packs p JOIN pack_auth_services s ON s.service_id=p.service_id
               WHERE s.merchant_wallet=$1
                 AND ($2::text IS NULL OR p.service_id=$2)
                 AND ($3::timestamptz IS NULL OR p.issued_at < $3)
               ORDER BY p.issued_at DESC LIMIT $4"#,
                &[&merchant_wallet, &service_id, &before, &fetch],
                "list packs",
            )
            .await?;
        let has_more = rows.len() as i64 > limit;
        Ok((
            rows.into_iter()
                .take(limit as usize)
                .map(pack_from_row)
                .collect(),
            has_more,
        ))
    }

    pub async fn list_revocations(
        &self,
        service_id: &str,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<(Vec<String>, DateTime<Utc>, bool), Error> {
        let rows = self.query(
            "SELECT jti::text AS jti, revoked_at FROM pack_auth_packs WHERE service_id=$1 AND revoked_at > $2 ORDER BY revoked_at ASC LIMIT $3",
            &[&service_id, &since, &(limit + 1)], "list revocations"
        ).await?;
        let complete = rows.len() as i64 <= limit;
        let rows: Vec<Row> = rows.into_iter().take(limit as usize).collect();
        let cursor = rows
            .last()
            .map(|row| row.get("revoked_at"))
            .unwrap_or_else(Utc::now);
        Ok((
            rows.iter().map(|row| row.get("jti")).collect(),
            cursor,
            complete,
        ))
    }

    pub async fn list_signing_keys(&self) -> Result<Vec<(String, Value)>, Error> {
        Ok(self
            .query(
                "SELECT kid, public_jwk FROM pack_auth_signing_keys ORDER BY active_from DESC",
                &[],
                "list signing keys",
            )
            .await?
            .into_iter()
            .map(|row| (row.get("kid"), row.get("public_jwk")))
            .collect())
    }

    pub async fn get_signing_key(&self, kid: &str) -> Result<Option<Value>, Error> {
        Ok(self
            .query_opt(
                "SELECT public_jwk FROM pack_auth_signing_keys WHERE kid=$1",
                &[&kid],
                "get signing key",
            )
            .await?
            .map(|row| row.get("public_jwk")))
    }

    pub async fn list_marketplace(
        &self,
        category: Option<&str>,
        tags: &[String],
        q: Option<&str>,
        limit: i64,
        cursor: Option<(DateTime<Utc>, String)>,
    ) -> Result<(Vec<MarketplaceRow>, bool), Error> {
        let tags = serde_json::json!(tags);
        let q = q.map(|value| format!("%{value}%"));
        let (cursor_time, cursor_id) =
            cursor.map_or((None, None), |(time, id)| (Some(time), Some(id)));
        let rows = self.query(
            r#"SELECT service_id, merchant_wallet, service_url, resources_allowlist, pack_bundles, created_at, updated_at
               FROM pack_auth_services WHERE status='active'
                 AND ($1::text IS NULL OR category=$1)
                 AND ($2::jsonb='[]'::jsonb OR tags @> $2)
                 AND ($3::text IS NULL OR service_id ILIKE $3 OR pack_bundles->'display'->>'name' ILIKE $3)
                 AND ($4::timestamptz IS NULL OR (updated_at, service_id) < ($4, $5))
               ORDER BY updated_at DESC, service_id DESC LIMIT $6"#,
            &[&category, &tags, &q, &cursor_time, &cursor_id, &(limit + 1)], "list marketplace"
        ).await?;
        let has_more = rows.len() as i64 > limit;
        Ok((
            rows.into_iter()
                .take(limit as usize)
                .map(marketplace_from_row)
                .collect(),
            has_more,
        ))
    }

    pub async fn get_marketplace(&self, service_id: &str) -> Result<Option<MarketplaceRow>, Error> {
        Ok(self.query_opt("SELECT service_id, merchant_wallet, service_url, resources_allowlist, pack_bundles, created_at, updated_at FROM pack_auth_services WHERE service_id=$1 AND status='active'", &[&service_id], "get marketplace item").await?.map(marketplace_from_row))
    }

    async fn execute(
        &self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
        label: &str,
    ) -> Result<u64, Error> {
        let client = self.conn().await?;
        if let Err(error) = open_transaction(&client, label).await {
            discard(client);
            return Err(error);
        }
        let result = wire(client.execute(sql, params), label).await;
        finish(client, result, label).await
    }

    async fn query_opt(
        &self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
        label: &str,
    ) -> Result<Option<Row>, Error> {
        let client = self.conn().await?;
        if let Err(error) = open_transaction(&client, label).await {
            discard(client);
            return Err(error);
        }
        let result = wire(client.query_opt(sql, params), label).await;
        finish(client, result, label).await
    }

    async fn query(
        &self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
        label: &str,
    ) -> Result<Vec<Row>, Error> {
        let client = self.conn().await?;
        if let Err(error) = open_transaction(&client, label).await {
            discard(client);
            return Err(error);
        }
        let result = wire(client.query(sql, params), label).await;
        finish(client, result, label).await
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}
fn service_from_row(row: Row) -> ServiceRow {
    ServiceRow {
        service_id: row.get("service_id"),
        merchant_wallet: row.get("merchant_wallet"),
        service_url: row.get("service_url"),
        resources_allowlist: row.get("resources_allowlist"),
        pack_bundles: row.get("pack_bundles"),
        status: row.get("status"),
    }
}
fn pack_from_row(row: Row) -> PackRow {
    PackRow {
        jti: row.get("jti"),
        service_id: row.get("service_id"),
        payer: row.get("payer"),
        pack_id: row.get("pack_id"),
        total_uses: row.get("total_uses"),
        used_uses: row.get("used_uses"),
        resources: row.get("resources"),
        issued_at: row.get("issued_at"),
        expires_at: row.get("expires_at"),
        revoked_at: row.get("revoked_at"),
    }
}
fn marketplace_from_row(row: Row) -> MarketplaceRow {
    MarketplaceRow {
        service_id: row.get("service_id"),
        merchant_wallet: row.get("merchant_wallet"),
        service_url: row.get("service_url"),
        resources_allowlist: row.get("resources_allowlist"),
        pack_bundles: row.get("pack_bundles"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

async fn open_transaction(client: &Client, label: &str) -> Result<(), Error> {
    wire(client.batch_execute("BEGIN"), label).await?;
    if let Err(error) = wire(
        client.batch_execute("SET LOCAL statement_timeout='25s'"),
        label,
    )
    .await
    {
        rollback(client, label).await;
        return Err(error);
    }
    if let Err(error) = wire(client.batch_execute("DEALLOCATE ALL"), label).await {
        rollback(client, label).await;
        return Err(error);
    }
    Ok(())
}
async fn commit(client: &Client, label: &str) -> Result<(), Error> {
    wire(client.batch_execute("COMMIT"), label).await
}
async fn rollback(client: &Client, label: &str) {
    let _ = timeout(AuthDb::WIRE_TIMEOUT, client.batch_execute("ROLLBACK")).await;
    tracing::debug!(label, "transaction rolled back");
}
fn discard(client: Client) {
    drop(Client::take(client));
}

async fn finish<T>(client: Client, result: Result<T, Error>, label: &str) -> Result<T, Error> {
    match result {
        Ok(value) => {
            if let Err(error) = commit(&client, label).await {
                discard(client);
                Err(error)
            } else {
                Ok(value)
            }
        }
        Err(error) => {
            rollback(&client, label).await;
            discard(client);
            Err(error)
        }
    }
}

async fn wire<T, F>(future: F, label: &str) -> Result<T, Error>
where
    F: std::future::Future<Output = Result<T, tokio_postgres::Error>>,
{
    timeout(AuthDb::WIRE_TIMEOUT, future)
        .await
        .map_err(|_| Error::Internal(format!("{label} timed out")))?
        .map_err(|error| Error::Internal(format!("{label}: {error}")))
}
