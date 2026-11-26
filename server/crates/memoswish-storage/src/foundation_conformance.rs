//! 双后端共用的规范历史升级、失败回滚与持久责任回归。

pub(crate) const REQUIRED_SCHEMA_OBJECTS: &[&str] = &[
    "user_profiles",
    "memberships_user",
    "tenant_audit_order",
    "auth_browser_expiry",
    "oauth_requests_expiry",
    "oauth_grants_expiry",
    "oauth_tokens_grant",
    "oidc_attempt_expiry",
    "recent_auth_expiry",
    "oidc_handoffs_expiry",
    "oidc_attempt_identity",
    "oidc_handoff_attempt",
    "jobs_due",
    "jobs_schedule",
];

pub(crate) const LEGACY_DATA: &str = r#"
INSERT INTO tenants VALUES('foundation','Foundation','free','2026-11-01T00:00:00Z');
INSERT INTO tenants VALUES('other','Other','free','2026-11-01T00:00:00Z');
INSERT INTO users VALUES('account','foundation','legacy@example.com','Legacy','preserved-password','owner','2026-11-01T00:00:00Z');
INSERT INTO users VALUES('learner','foundation','learner@example.com','Learner','learner-password','learner','2026-11-01T00:00:00Z');
INSERT INTO api_tokens(id,tenant_id,user_id,name,token_hash,scopes,created_at) VALUES('api','foundation','account','Agent','preserved-hash','["content:read"]','2026-11-01T00:00:00Z');
INSERT INTO usage_counters VALUES('foundation','tts_chars','2026-11',123);
INSERT INTO decks VALUES('deck','foundation','Deck','Description','en','["legacy"]','2026-11-01T00:00:00Z');
INSERT INTO cards VALUES('card','foundation','deck','basic',7,'{"legacy":true}','2026-11-01T00:00:00Z','2026-11-01T00:00:00Z');
INSERT INTO memory_states(tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures,last_rating) VALUES('foundation','account','card',3.5,4.5,3,1,9,2);
INSERT INTO feedback_events VALUES('foundation','account','event','session','card',2,'{"legacy":true}','2026-11-01T00:00:00Z');
INSERT INTO feed_sessions VALUES('session','foundation','account',17,'["card"]','2026-11-01T00:00:00Z','2026-11-01T00:00:00Z');
INSERT INTO oauth_clients VALUES('client',2000000000,'{"legacy":"client"}');
INSERT INTO auth_browser_sessions VALUES('browser','foundation','account',2000000000,'{"legacy":"browser"}');
INSERT INTO oauth_authorization_requests VALUES('request','browser','client',2000000000,'{"legacy":"request"}');
INSERT INTO oauth_grants VALUES('grant','foundation','account','client',2000000000,0,'{"legacy":"metadata"}');
INSERT INTO oauth_authorization_codes VALUES('code','foundation','grant',2000000000,1,'{"legacy":"code"}');
INSERT INTO oauth_tokens VALUES('access','foundation','grant','access',2000000000,0,'{"legacy":"access"}');
INSERT INTO oauth_tokens VALUES('refresh','foundation','grant','refresh',2000000000,1,'{"legacy":"refresh"}');
INSERT INTO federated_identities VALUES('https://issuer.example','subject','foundation','account','{"client_id":"client","issuer":"https://issuer.example","subject":"subject","provider":"provider","tenant_id":"foundation","user_id":"account","email":null,"email_verified":false,"display_name":null,"created_at":1793491200,"authenticated_at":1793491200}','encrypted-revocation-material');
INSERT INTO identity_status VALUES('https://issuer.example','subject',1793491200,'email-enabled','enabled',0,0);
INSERT INTO oidc_attempts VALUES('attempt','state','launch','browser','provider',2,2000000000,'{"legacy":"attempt"}','foundation','account',9,'https://issuer.example','subject');
INSERT INTO oidc_handoffs VALUES('handoff','provider','challenge','foundation','account',2000000000,'{"legacy":"handoff"}','attempt');
INSERT INTO recent_authentication VALUES('recent','foundation','account',2000000000);
INSERT INTO user_auth_epochs VALUES('foundation','account',7);
INSERT INTO identity_events VALUES('https://issuer.example','event-hash',2000000000);
INSERT INTO identity_unlink_fences VALUES('canonical-hash',8);
UPDATE oidc_sequence SET value=9;
INSERT INTO erased_tenants VALUES('deleted-tenant');
INSERT INTO erased_users VALUES('other','deleted-account');
INSERT INTO account_erasure_jobs VALUES('cleanup','{"id":"cleanup","tenant_id":"deleted-tenant","purge_assets":true,"credentials":[["apple","encrypted-cleanup-material"]]}',2000000000000);
"#;

pub(crate) const SNAPSHOTS: &[(&str, &str)] = &[
    ("users", "id,tenant_id,email,display_name,password_hash,role,created_at"),
    ("api_tokens", "id,tenant_id,user_id,name,token_hash,scopes,created_at,expires_at,last_used_at,revoked"),
    ("usage_counters", "tenant_id,metric,period,amount"),
    ("decks", "id,tenant_id,title,description,language,tags,created_at"),
    ("cards", "id,tenant_id,deck_id,template,revision,body,created_at,updated_at"),
    (
        "memory_states",
        "tenant_id,user_id,card_id,stability,difficulty,reps,lapses,exposures,last_review,due,starred,last_rating",
    ),
    ("feedback_events", "tenant_id,user_id,event_id,session_id,card_id,rating,body,received_at"),
    ("feed_sessions", "id,tenant_id,user_id,next_slot,recent_card_ids,created_at,updated_at"),
    ("oauth_clients", "id,expires_at,body"),
    ("auth_browser_sessions", "hash,tenant_id,user_id,expires_at,body"),
    ("oauth_authorization_requests", "id,browser_hash,client_id,expires_at,body"),
    ("oauth_grants", "id,tenant_id,user_id,client_id,expires_at,revoked,metadata"),
    ("oauth_authorization_codes", "hash,tenant_id,grant_id,expires_at,consumed,body"),
    ("oauth_tokens", "hash,tenant_id,grant_id,kind,expires_at,consumed,body"),
    ("federated_identities", "issuer,subject,tenant_id,user_id,body,credential"),
    (
        "identity_status",
        "issuer,subject,last_event_at,last_event_kind,email_forwarding,revoked_before,permanently_deleted",
    ),
    (
        "oidc_attempts",
        "id,state_hash,launch_hash,browser_hash,provider,phase,expires_at,body,tenant_id,user_id,sequence,identity_issuer,identity_subject",
    ),
    ("oidc_handoffs", "hash,provider,challenge,tenant_id,user_id,expires_at,body,attempt_id"),
    ("recent_authentication", "hash,tenant_id,user_id,expires_at"),
    ("user_auth_epochs", "tenant_id,user_id,generation"),
    ("identity_events", "issuer,event_hash,expires_at"),
    ("identity_unlink_fences", "identity_hash,sequence"),
    ("oidc_sequence", "id,value"),
    ("erased_tenants", "tenant_id"),
    ("erased_users", "tenant_id,user_id"),
    ("account_erasure_jobs", "id,body"),
];

pub(crate) fn through(full: &sqlx::migrate::Migrator, version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(full.iter().filter(|m| m.version <= version).cloned().collect()),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

macro_rules! foundation_tests {
    ($pool:ty, $repo:ident, $migrations:literal, $corrupt_legacy:literal) => {
        use crate::foundation_conformance::{LEGACY_DATA, SNAPSHOTS, through};
        use memoswish_core::identity::IdentityRepo;

        async fn registration_contenders(repo: &$repo) -> (UserRecord, UserRecord) {
            repo.upsert_tenant(&TenantRecord {
                id: "registration".into(), name: "Registration".into(), plan: "free".into(), created_at: Utc::now(),
            }).await.unwrap();
            let winner = UserRecord {
                id: "registration-winner".into(), tenant_id: "registration".into(), email: "overlap@example.com".into(),
                display_name: "Registration".into(), password_hash: "preserved-password".into(), role: Role::Learner,
                created_at: Utc::now(),
            };
            let loser = UserRecord { id: "registration-loser".into(), ..winner.clone() };
            (winner, loser)
        }

        async fn assert_registration_winner(repo: &$repo, winner: &UserRecord, loser: &UserRecord) {
            assert_eq!(repo.find_user_by_email(&winner.email).await.unwrap().unwrap().id, winner.id);
            assert!(repo.get_user(&winner.tenant_id, &winner.id).await.unwrap().is_some());
            assert!(repo.get_user(&loser.tenant_id, &loser.id).await.unwrap().is_none());
            for (table, column) in [
                ("users", "id"), ("account_auth_epochs", "user_id"),
                ("membership_generations", "user_id"), ("tenant_memberships", "user_id"),
            ] {
                for (id, expected) in [(&winner.id, 1_i64), (&loser.id, 0_i64)] {
                    let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {column}=$1"))
                        .bind(id).fetch_one(repo.pool()).await.unwrap();
                    assert_eq!(count, expected, "unexpected registration rows in {table} for {id}");
                }
            }
        }

        async fn snapshot(pool: &$pool, upgraded: bool) -> Vec<Vec<Vec<Option<String>>>> {
            let mut result = Vec::new();
            for (table, columns) in SNAPSHOTS {
                let source = if *table == "users" && upgraded { "user_profiles" } else { table };
                let projection = columns.split(',').map(|column| format!("CAST({column} AS TEXT)")).collect::<Vec<_>>().join(",");
                let rows = sqlx::query(&format!("SELECT {projection} FROM {source} ORDER BY {projection}"))
                    .fetch_all(pool).await.unwrap();
                result.push(rows.iter().map(|row| (0..columns.split(',').count()).map(|i| row.get(i)).collect()).collect());
            }
            result
        }

        async fn populated_upgrade(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            through(&full, 8).run(pool).await.unwrap();
            sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();
            let before = snapshot(pool, false).await;

            // 在约束创建之后注入错误，复制及 DROP 均必须随 SQLx 事务回滚。
            let mut broken = through(&full, 9);
            let sql = format!("{}\nSELECT * FROM injected_missing_table;", broken.migrations.last().unwrap().sql);
            broken.migrations.to_mut()[8] = sqlx::migrate::Migration::new(
                9, "injected failure".into(), sqlx::migrate::MigrationType::Simple, sql.into(), false,
            );
            assert!(broken.run(pool).await.is_err());
            assert_eq!(snapshot(pool, false).await, before);
            let versions: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(versions, 8);

            through(&full, 9).run(pool).await.unwrap();
            assert_eq!(snapshot(pool, true).await, before);
            let legacy_deadline:i64=sqlx::query_scalar("SELECT drain_until_ms FROM account_erasure_jobs WHERE id='cleanup'").fetch_one(pool).await.unwrap();
            assert_eq!(legacy_deadline,2000000000000);
            through(&full, 9).run(pool).await.unwrap();
            assert_eq!(snapshot(pool, true).await, before);
            through(&full,31).run(pool).await.unwrap();
            let hash_before: String=sqlx::query_scalar("SELECT password_hash FROM users WHERE id='account'").fetch_one(pool).await.unwrap();
            let mut broken_password=through(&full,32);
            let sql=format!("{}\nSELECT * FROM injected_password_missing_table;",broken_password.migrations.last().unwrap().sql);
            let password_index=broken_password.migrations.len()-1;
            broken_password.migrations.to_mut()[password_index]=sqlx::migrate::Migration::new(32,"injected password failure".into(),sqlx::migrate::MigrationType::Simple,sql.into(),false);
            assert!(broken_password.run(pool).await.is_err());
            let last:i64=sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations").fetch_one(pool).await.unwrap();
            assert_eq!(last,full.iter().filter(|m|m.version<32).map(|m|m.version).max().unwrap());
            assert_eq!(sqlx::query_scalar::<_,String>("SELECT password_hash FROM users WHERE id='account'").fetch_one(pool).await.unwrap(),hash_before);
            full.run(pool).await.unwrap();
            let repo = $repo { observer: memoswish_core::observability::noop(), pool: pool.clone(), learning_gate: None, feed_gate: None, content_gate: None, lifecycle_gate: None };
            let user = repo.get_user("foundation", "account").await.unwrap().unwrap();
            let proof=memoswish_core::password_lifecycle::PasswordLifecycleRepo::password_snapshot(&repo,&user.email).await.unwrap().unwrap();
            assert!(!proof.verified);
            assert_eq!(proof.password_hash,"preserved-password");
            assert_eq!(proof.version,0);
            assert_eq!(proof.generation,7);
            assert_eq!(user.password_hash, "preserved-password");
            assert_eq!(user.role, Role::Owner);
            assert_eq!(repo.find_user_by_email("LEGACY@EXAMPLE.COM").await.unwrap().unwrap(), user);
            assert_eq!(repo.identity_generation("foundation", "account").await.unwrap(), 7);
            assert_eq!(repo.identity_list("foundation", "account").await.unwrap()[0].subject, "subject");
            assert_eq!(repo.account_erasure_jobs().await.unwrap()[0].credentials[0].1, "encrypted-cleanup-material");
            assert_eq!(repo.get_usage("foundation", "tts_chars", "2026-11").await.unwrap(), 123);
            for table in ["account_auth_epochs", "membership_generations", "tenant_memberships"] {
                let generation: i64 = sqlx::query_scalar(&format!("SELECT generation FROM {table} WHERE user_id='account'"))
                    .fetch_one(pool).await.unwrap();
                assert_eq!(generation, 7);
            }
            assert!(sqlx::query("UPDATE user_profiles SET role='learner' WHERE id='account'").execute(pool).await.is_err());
            assert!(sqlx::query("UPDATE users SET role='learner' WHERE id='account'").execute(pool).await.is_err());
            sqlx::query("UPDATE tenant_memberships SET role='editor' WHERE tenant_id='foundation' AND user_id='account'")
                .execute(pool).await.unwrap();
            assert_eq!(repo.get_user("foundation", "account").await.unwrap().unwrap().role, Role::Editor);

            // 同一账户在不同工作区保持各自角色；默认偏好只选择已有成员。
            sqlx::raw_sql("INSERT INTO membership_generations VALUES('other','account',3); INSERT INTO tenant_memberships(tenant_id,user_id,role,joined_at,generation) VALUES('other','account','learner','2026-11-01T00:00:00Z',3);")
                .execute(pool).await.unwrap();
            assert_eq!(repo.get_user("other", "account").await.unwrap().unwrap().role, Role::Learner);
            assert_eq!(repo.find_user_by_email(&user.email).await.unwrap().unwrap().tenant_id, "foundation");
            sqlx::query("UPDATE users SET default_tenant_id='other' WHERE id='account'").execute(pool).await.unwrap();
            assert_eq!(repo.find_user_by_email(&user.email).await.unwrap().unwrap().tenant_id, "other");
            assert!(repo.get_user("absent", "account").await.unwrap().is_none());
            assert!(sqlx::query("UPDATE tenant_memberships SET role='superuser' WHERE user_id='account'").execute(pool).await.is_err());
            assert!(sqlx::query("UPDATE tenant_memberships SET generation=99 WHERE user_id='account'").execute(pool).await.is_err());

            // 账户创建之后的成员失败不能留下账户、世代或历史；相同参数修复后可重试。
            sqlx::query("INSERT INTO erased_users VALUES('foundation','new-account')").execute(pool).await.unwrap();
            let mut new_user = user.clone();
            new_user.id = "new-account".into();
            new_user.email = "new@example.com".into();
            assert!(repo.insert_user(&new_user).await.is_err());
            for (table, column) in [("users", "id"), ("account_auth_epochs", "user_id"), ("membership_generations", "user_id")] {
                let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {column}='new-account'"))
                    .fetch_one(pool).await.unwrap();
                assert_eq!(count, 0);
            }
            sqlx::query("DELETE FROM erased_users WHERE user_id='new-account'").execute(pool).await.unwrap();
            repo.insert_user(&new_user).await.unwrap();
            let duplicate = UserRecord { id: "duplicate".into(), ..new_user.clone() };
            assert!(matches!(repo.insert_user(&duplicate).await, Err(CoreError::Conflict(_))));
            assert!(repo.get_user("foundation", "duplicate").await.unwrap().is_none());

            // 并发相同邮箱仅提交一个完整账户，失败者没有成员或世代残留。
            let racer_a = UserRecord { id: "racer-a".into(), email: "race@example.com".into(), ..user.clone() };
            let racer_b = UserRecord { id: "racer-b".into(), ..racer_a.clone() };
            let (a, b) = tokio::join!(repo.insert_user(&racer_a), repo.insert_user(&racer_b));
            assert_ne!(a.is_ok(), b.is_ok());
            let (winner, loser, failure) = if a.is_ok() { (&racer_a, &racer_b, b) } else { (&racer_b, &racer_a, a) };
            assert!(matches!(failure, Err(CoreError::Conflict(_))));
            assert!(repo.get_user("foundation", &winner.id).await.unwrap().is_some());
            assert!(repo.get_user("foundation", &loser.id).await.unwrap().is_none());
            let leftovers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM membership_generations WHERE user_id=$1")
                .bind(&loser.id).fetch_one(pool).await.unwrap();
            assert_eq!(leftovers, 0);

            durable_responsibility(pool).await;
        }

        async fn durable_responsibility(pool: &$pool) {
            for (index, state) in ["queued", "running", "succeeded", "dead"].iter().enumerate() {
                let sql = format!("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,state,attempts,max_attempts,available_at_ms,lease_until_ms,worker,token,result,error) VALUES('foundation','job{index}','synthesis','key{index}','{{\"text\":\"preserve\"}}','account',7,'{state}',2,3,100,200,'worker','claim-token','{{\"asset\":\"exact-version\"}}','preserved error')");
                sqlx::query(&sql).execute(pool).await.unwrap();
            }
            for (index, state) in ["reserved", "committed", "released"].iter().enumerate() {
                sqlx::query(&format!("INSERT INTO quota_operations VALUES('foundation','job{index}','tts_chars','2026-11',17,'{state}')"))
                    .execute(pool).await.unwrap();
            }
            sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES('foundation','internal','cleanup','internal','{}',3,100)")
                .execute(pool).await.unwrap();
            assert!(sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('other','bad','test','bad','{}','account',7,3,100)")
                .execute(pool).await.is_err());
            assert!(sqlx::query("INSERT INTO quota_operations VALUES('other','job0','tts_chars','2026-11',17,'reserved')").execute(pool).await.is_err());
            assert!(sqlx::query("DELETE FROM background_jobs WHERE id='job0'").execute(pool).await.is_err());
            assert!(sqlx::query("UPDATE background_jobs SET tenant_id='other' WHERE id='internal'").execute(pool).await.is_err());
            assert!(sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES('foundation','duplicate-key','synthesis','key0','{}',3,100)").execute(pool).await.is_err());
            let jobs = job_snapshot(pool).await;
            let ledger = ledger_snapshot(pool).await;
            sqlx::query("DELETE FROM users WHERE id='account'").execute(pool).await.unwrap();
            assert_eq!(job_snapshot(pool).await, jobs);
            assert_eq!(ledger_snapshot(pool).await, ledger);
            assert!(sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,user_id,requester_generation,max_attempts,available_at_ms) VALUES('foundation','late','test','late','{}','account',7,3,100)").execute(pool).await.is_err());
            sqlx::raw_sql("INSERT INTO erased_tenants VALUES('foundation'); DELETE FROM tenants WHERE id='foundation';").execute(pool).await.unwrap();
            assert_eq!(job_snapshot(pool).await, jobs);
            assert_eq!(ledger_snapshot(pool).await, ledger);
            assert!(sqlx::query("INSERT INTO background_jobs(tenant_id,id,kind,idempotency_key,payload,max_attempts,available_at_ms) VALUES('foundation','late-internal','cleanup','late-internal','{}',3,100)").execute(pool).await.is_err());
            sqlx::query("UPDATE background_jobs SET state='succeeded',result='{}' WHERE id='internal'").execute(pool).await.unwrap();
            sqlx::query("UPDATE quota_operations SET state='released' WHERE operation_id='job0'").execute(pool).await.unwrap();
            let cleanup: String = sqlx::query_scalar("SELECT body FROM account_erasure_jobs WHERE id='cleanup'").fetch_one(pool).await.unwrap();
            assert!(cleanup.contains("encrypted-cleanup-material"));
        }

        async fn job_snapshot(pool: &$pool) -> Vec<Vec<Option<String>>> {
            let rows = sqlx::query("SELECT tenant_id,id,kind,idempotency_key,CAST(payload AS TEXT),user_id,CAST(requester_generation AS TEXT),state,CAST(attempts AS TEXT),CAST(max_attempts AS TEXT),CAST(available_at_ms AS TEXT),CAST(lease_until_ms AS TEXT),worker,token,CAST(result AS TEXT),error FROM background_jobs WHERE kind<>'erasure' ORDER BY id")
                .fetch_all(pool).await.unwrap();
            rows.iter().map(|row| (0..16).map(|i| row.get(i)).collect()).collect()
        }

        async fn ledger_snapshot(pool: &$pool) -> Vec<Vec<Option<String>>> {
            let rows = sqlx::query("SELECT tenant_id,operation_id,metric,period,CAST(amount AS TEXT),state FROM quota_operations ORDER BY operation_id")
                .fetch_all(pool).await.unwrap();
            rows.iter().map(|row| (0..6).map(|i| row.get(i)).collect()).collect()
        }

        async fn invalid_legacy(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            through(&full, 8).run(pool).await.unwrap();
            sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();
            sqlx::query("UPDATE users SET role='invalid-role' WHERE id='account'").execute(pool).await.unwrap();
            let before = snapshot(pool, false).await;
            assert!(full.run(pool).await.is_err());
            assert_eq!(snapshot(pool, false).await, before);
            sqlx::query("UPDATE users SET role='owner' WHERE id='account'").execute(pool).await.unwrap();
            sqlx::raw_sql($corrupt_legacy).execute(pool).await.unwrap();
            let orphaned = snapshot(pool, false).await;
            assert!(full.run(pool).await.is_err());
            assert_eq!(snapshot(pool, false).await, orphaned);
            sqlx::query("UPDATE feed_sessions SET user_id='account' WHERE id='session'").execute(pool).await.unwrap();
            full.run(pool).await.unwrap();
        }

        async fn dependency_conflict(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            through(&full, 8).run(pool).await.unwrap();
            sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();
            sqlx::raw_sql("CREATE TABLE legacy_job_dependency(tenant_id TEXT NOT NULL,user_id TEXT NOT NULL,payload TEXT NOT NULL,FOREIGN KEY(tenant_id,user_id) REFERENCES users(tenant_id,id) ON DELETE CASCADE); INSERT INTO legacy_job_dependency VALUES('foundation','account','preserve requester');")
                .execute(pool).await.unwrap();
            assert!(full.run(pool).await.is_err(), "unmapped dependencies must fail transactionally");
            let payload: String = sqlx::query_scalar("SELECT payload FROM legacy_job_dependency").fetch_one(pool).await.unwrap();
            assert_eq!(payload, "preserve requester");
            assert_eq!(snapshot(pool, false).await[0].len(), 2);
            sqlx::query("DROP TABLE legacy_job_dependency").execute(pool).await.unwrap();
            full.run(pool).await.unwrap();
        }

        async fn rejected_histories(pool: &$pool) {
            let full = sqlx::migrate!($migrations);
            through(&full, 8).run(pool).await.unwrap();
            sqlx::raw_sql(LEGACY_DATA).execute(pool).await.unwrap();
            let before = snapshot(pool, false).await;
            sqlx::query("UPDATE _sqlx_migrations SET version=999 WHERE version=8").execute(pool).await.unwrap();
            assert!(matches!(full.run(pool).await, Err(sqlx::migrate::MigrateError::VersionMissing(999))));
            assert_eq!(snapshot(pool, false).await, before);
            let repo_error = $repo::migrate(pool).await.unwrap_err().to_string();
            assert!(repo_error.contains("canonical main migration history"), "{repo_error}");
            sqlx::query("UPDATE _sqlx_migrations SET version=8 WHERE version=999").execute(pool).await.unwrap();
            sqlx::query("UPDATE _sqlx_migrations SET checksum=(SELECT checksum FROM _sqlx_migrations WHERE version=7) WHERE version=8").execute(pool).await.unwrap();
            assert!(matches!(full.run(pool).await, Err(sqlx::migrate::MigrateError::VersionMismatch(8))));
            sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=8").bind(full.iter().find(|m| m.version==8).unwrap().checksum.as_ref()).execute(pool).await.unwrap();
            sqlx::query("UPDATE _sqlx_migrations SET success=false WHERE version=8").execute(pool).await.unwrap();
            assert!(matches!(full.run(pool).await, Err(sqlx::migrate::MigrateError::Dirty(8))));
            sqlx::query("UPDATE _sqlx_migrations SET success=true WHERE version=8").execute(pool).await.unwrap();
            // 0005 在 SQLite 中是空操作，SQLx 会补写缺失历史，需在运行前拒绝缺口。
            sqlx::query("DELETE FROM _sqlx_migrations WHERE version=5").execute(pool).await.unwrap();
            let error = $repo::migrate(pool).await.unwrap_err().to_string();
            assert!(error.contains("incomplete at version 5"), "{error}");
            assert_eq!(snapshot(pool, false).await, before);
            let restored = full.iter().find(|m| m.version == 5).unwrap();
            sqlx::query("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES(5,'erasure write locks',true,$1,0)")
                .bind(restored.checksum.as_ref()).execute(pool).await.unwrap();
            full.run(pool).await.unwrap();
        }
    };
}
pub(crate) use foundation_tests;
