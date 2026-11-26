//! 恢复候选与运维投影的唯一登记入口；分页、权限、租约和完成事务仍由原入口负责。

pub(crate) struct Authority {
    pub name: &'static str,
    pub sql: &'static str,
    // 投影统一为 kind、tenant_id、id、since_ms；同一责任可被多个恢复入口发现。
    pub metrics: &'static str,
}

impl Authority {
    pub fn at(&self, clock: &str) -> String {
        self.sql.replace("{now_ms}", clock)
    }
}

macro_rules! retained_api_sql {
    () => {
        "SELECT tenant_id,id,expires_at FROM api_tokens WHERE expires_at IS NOT NULL"
    };
}
pub(crate) use retained_api_sql;

macro_rules! import_followups_sql {
    () => {
        "SELECT tenant_id,import_id,card_id,revision FROM import_followups WHERE outcome IN ('pending','running')"
    };
}
macro_rules! provider_attempts_sql {
    () => {
        "SELECT tenant_id,synthesis_id FROM tts_provider_attempts WHERE outcome='uncertain'"
    };
}

// 每项权威必须同时声明候选及指标投影，并自动加入全集，避免手工列表漏项。
macro_rules! authorities {
    ($($name:ident { $($body:tt)* })+) => {
        $(pub(crate) const $name: Authority = Authority { $($body)* };)+
        pub(crate) const AUTHORITIES: &[Authority] = &[$($name),+];
    };
}

authorities! {
    IMPORTS {
        name: "imports",
        sql: concat!("SELECT i.tenant_id,i.id FROM content_imports i WHERE i.outcome='pending' OR EXISTS(SELECT 1 FROM (",import_followups_sql!(),") f WHERE f.tenant_id=i.tenant_id AND f.import_id=i.id) OR EXISTS(SELECT 1 FROM import_uploads u JOIN asset_upload_attempts a ON a.tenant_id=u.tenant_id AND a.intent_id=u.intent_id JOIN asset_upload_intents x ON x.tenant_id=u.tenant_id AND x.id=u.intent_id WHERE u.tenant_id=i.tenant_id AND u.import_id=i.id AND a.outcome<>'cleaned' AND (x.published_attempt IS NULL OR x.published_attempt<>a.id))"),
        metrics: "SELECT 'import',r.tenant_id,r.id,j.enqueued_at_ms FROM imports r LEFT JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.id",
    }
    IMPORT_FOLLOWUPS {
        name: "followups",
        sql: import_followups_sql!(),
        metrics: "SELECT 'import',r.tenant_id,r.import_id,j.enqueued_at_ms FROM followups r LEFT JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.import_id",
    }
    IMPORT_CLEANUP {
        name: "import_cleanup",
        sql: "SELECT a.tenant_id,u.import_id,a.id,a.store_id FROM asset_upload_attempts a JOIN import_uploads u ON u.tenant_id=a.tenant_id AND a.intent_id=u.intent_id JOIN content_imports i ON i.tenant_id=u.tenant_id AND i.id=u.import_id JOIN asset_upload_intents x ON x.tenant_id=a.tenant_id AND x.id=a.intent_id WHERE i.outcome<>'pending' AND a.outcome IN ('uploaded','cleanup_pending') AND a.version_kind<>'unknown' AND (x.published_attempt IS NULL OR x.published_attempt<>a.id)",
        metrics: "SELECT 'import',r.tenant_id,r.import_id,j.enqueued_at_ms FROM import_cleanup r LEFT JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.import_id",
    }
    SPEECH {
        name: "speech",
        sql: "SELECT s.tenant_id,s.id FROM tts_syntheses s JOIN tenants t ON t.id=s.tenant_id WHERE NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=s.tenant_id) AND NOT EXISTS(SELECT 1 FROM asset_upload_intents i WHERE i.tenant_id=s.tenant_id AND i.id=s.upload_id AND i.published_attempt IS NOT NULL)",
        metrics: "SELECT 'speech',r.tenant_id,r.id,j.enqueued_at_ms FROM speech r LEFT JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.id",
    }
    BGM {
        name: "bgm",
        sql: "SELECT tenant_id,id FROM bgm_publications b WHERE outcome='pending' AND NOT EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=b.tenant_id)",
        metrics: "SELECT 'bgm',r.tenant_id,r.id,j.enqueued_at_ms FROM bgm r LEFT JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.id",
    }
    ATTACHMENTS {
        name: "attachments",
        sql: "SELECT tenant_id,item_id FROM tts_submission_items WHERE receipt IS NULL",
        // 共享合成的多个待挂载项只计一个 speech 责任，直到最后一份回执落盘。
        metrics: "SELECT 'speech',r.tenant_id,COALESCE(s.synthesis_id,'attachment:'||r.item_id),j.enqueued_at_ms FROM attachments r LEFT JOIN tts_requesters s ON s.tenant_id=r.tenant_id AND s.id=r.item_id LEFT JOIN background_jobs j ON j.tenant_id=s.tenant_id AND j.id=s.synthesis_id",
    }
    PROVIDERS {
        name: "providers",
        sql: provider_attempts_sql!(),
        metrics: "SELECT 'speech',r.tenant_id,r.synthesis_id,j.enqueued_at_ms FROM providers r LEFT JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=r.synthesis_id",
    }
    ASSETS {
        name: "assets",
        sql: "SELECT i.tenant_id,i.id FROM asset_upload_intents i JOIN asset_records a ON a.tenant_id=i.tenant_id AND a.id=i.asset_id WHERE (i.published_attempt IS NULL AND NOT EXISTS(SELECT 1 FROM asset_upload_attempts u WHERE u.tenant_id=i.tenant_id AND u.intent_id=i.id)) OR EXISTS(SELECT 1 FROM asset_upload_attempts u WHERE u.tenant_id=i.tenant_id AND u.intent_id=i.id AND u.outcome<>'cleaned' AND (i.published_attempt IS NULL OR u.id<>i.published_attempt))",
        metrics: "SELECT CASE WHEN s.id IS NOT NULL THEN 'speech' WHEN u.import_id IS NOT NULL THEN 'import' WHEN b.id IS NOT NULL THEN 'bgm' ELSE 'asset' END,r.tenant_id,COALESCE(s.id,u.import_id,r.id),j.enqueued_at_ms FROM assets r LEFT JOIN bgm_publications b ON b.tenant_id=r.tenant_id AND b.id=r.id LEFT JOIN tts_syntheses s ON s.tenant_id=r.tenant_id AND s.upload_id=r.id LEFT JOIN import_uploads u ON u.tenant_id=r.tenant_id AND u.intent_id=r.id LEFT JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=COALESCE(s.id,u.import_id,r.id)",
    }
    ERASURES {
        name: "erasures",
        sql: "SELECT e.*,e.partition_id AS tenant_id,j.state FROM account_erasure_jobs e JOIN background_jobs j ON j.tenant_id=e.partition_id AND j.id=e.id AND j.kind='erasure' WHERE e.progress<>'complete'",
        metrics: "SELECT 'erasure',partition_id,id,responsibility_at_ms FROM erasures",
    }
    OBJECTS {
        name: "objects",
        sql: "SELECT 'asset' AS source,tenant_id,id,store_id,object_key,version_kind,version_id,outcome,responsibility_at_ms FROM asset_upload_attempts WHERE outcome<>'cleaned' UNION ALL SELECT 'managed' AS source,tenant_id,id,store_id,object_key,version_kind,version_id,outcome,responsibility_at_ms FROM managed_object_writes WHERE outcome<>'cleaned'",
        // 正常发布对象仍是擦除扫描的候选，但在墓碑出现之前没有清理责任。
        metrics: "SELECT CASE source WHEN 'asset' THEN 'orphan' ELSE 'managed_write' END,tenant_id,id,responsibility_at_ms FROM objects o WHERE outcome<>'uploaded' OR EXISTS(SELECT 1 FROM erased_tenants e WHERE e.tenant_id=o.tenant_id) OR (source='asset' AND NOT EXISTS(SELECT 1 FROM asset_upload_intents i WHERE i.tenant_id=o.tenant_id AND i.published_attempt=o.id))",
    }
    TOMBSTONES {
        name: "tombstones",
        sql: "SELECT tenant_id FROM erased_tenants",
        // 永久墓碑是周期扫描入口；只观察它关联的未完成责任，不把扫描标记当作新任务。
        metrics: "SELECT 'erasure',e.partition_id,e.id,e.responsibility_at_ms FROM tombstones t JOIN erasures e ON e.partition_id=t.tenant_id",
    }
    JOBS {
        name: "jobs",
        sql: "SELECT j.* FROM background_jobs j WHERE j.work_scope<>'maintenance' AND j.kind NOT IN ('erasure','managed_put','explanation') AND (j.state<>'succeeded' OR EXISTS(SELECT 1 FROM quota_operations q WHERE q.tenant_id=j.tenant_id AND q.operation_id=j.id AND q.state='reserved'))",
        metrics: "SELECT CASE WHEN s.id IS NOT NULL THEN 'speech' WHEN u.import_id IS NOT NULL THEN 'import' WHEN b.id IS NOT NULL THEN 'bgm' ELSE CASE r.kind WHEN 'tts_synthesis' THEN 'speech' WHEN 'tts_upload' THEN 'speech' WHEN 'asset_upload' THEN 'asset' WHEN 'content_import' THEN 'import' ELSE 'other' END END,r.tenant_id,COALESCE(s.id,u.import_id,r.id),CASE WHEN s.id IS NOT NULL OR u.import_id IS NOT NULL THEN j.enqueued_at_ms ELSE r.enqueued_at_ms END FROM jobs r LEFT JOIN bgm_publications b ON b.tenant_id=r.tenant_id AND b.id=r.id LEFT JOIN tts_syntheses s ON s.tenant_id=r.tenant_id AND s.upload_id=r.id LEFT JOIN import_uploads u ON u.tenant_id=r.tenant_id AND u.intent_id=r.id LEFT JOIN background_jobs j ON j.tenant_id=r.tenant_id AND j.id=COALESCE(s.id,u.import_id)",
    }
    RETAINED_SPEECH {
        name: "retained_speech",
        sql: concat!("SELECT s.tenant_id,s.id,j.available_at_ms FROM tts_syntheses s JOIN background_jobs j ON j.tenant_id=s.tenant_id AND j.id=s.id WHERE j.state='dead' AND s.upload_id IS NULL AND (s.work<>'{}' OR s.audio IS NOT NULL OR s.metadata IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM (",provider_attempts_sql!(),") p WHERE p.tenant_id=s.tenant_id AND p.synthesis_id=s.id) AND NOT EXISTS(SELECT 1 FROM quota_operations q WHERE q.tenant_id=s.tenant_id AND q.operation_id=s.id AND q.state='reserved') AND NOT EXISTS(SELECT 1 FROM tts_requesters r WHERE r.tenant_id=s.tenant_id AND r.synthesis_id=s.id AND r.outcome IN ('pending','published','attached'))"),
        // 没有运营方保留策略时只能报告候选，不能伪造到期年龄。
        metrics: "SELECT 'speech',tenant_id,id,CAST(NULL AS BIGINT) FROM retained_speech",
    }
    RETAINED_API {
        name: "retained_api",
        sql: retained_api_sql!(),
        metrics: "SELECT 'other',tenant_id,'api_metadata:'||id,CAST(NULL AS BIGINT) FROM retained_api WHERE {api_expiry_ms}<=(SELECT now_ms FROM clock)",
    }
    EXPLANATIONS {
        name: "explanations",
        sql: "SELECT * FROM explanation_operations",
        // 未决结算不会因正文过期、内容删除或屏蔽而消失。
        metrics: "SELECT 'explanation',e.tenant_id,e.id,j.enqueued_at_ms FROM explanations e JOIN background_jobs j ON j.tenant_id=e.tenant_id AND j.id=e.id WHERE e.state IN ('pending','unresolved') OR EXISTS(SELECT 1 FROM explanation_holds h WHERE h.tenant_id=e.tenant_id AND h.operation_id=e.id)",
    }
    EXPLANATION_RESULTS {
        name: "explanation_results",
        sql: "SELECT tenant_id,id,expires_at_ms FROM explanation_operations e WHERE result IS NOT NULL AND (expires_at_ms<={now_ms} OR NOT EXISTS(SELECT 1 FROM cards c WHERE c.tenant_id=e.tenant_id AND c.id=e.card_id AND c.revision=e.revision))",
        // P3.1 修订或删除可立即产生正文清理责任，不把未来 TTL 当作起算时间。
        metrics: "SELECT 'lifecycle',tenant_id,'explanation:'||id,CASE WHEN expires_at_ms<=(SELECT now_ms FROM clock) THEN expires_at_ms END FROM explanation_results",
    }
    DIAGNOSTICS {
        name: "diagnostics",
        sql: "SELECT tenant_id,user_id || ':' || report_id AS id,created_at_ms FROM diagnostic_reports WHERE dispatch_started=0 AND forward_authority IS NOT NULL AND expires_at_ms>{now_ms}",
        metrics: "SELECT 'diagnostic',tenant_id,id,created_at_ms FROM diagnostics",
    }
    DIAGNOSTIC_EXPIRY {
        name: "diagnostic_expiry",
        sql: "SELECT tenant_id,user_id,report_id,expires_at_ms FROM diagnostic_reports WHERE expires_at_ms<={now_ms}",
        metrics: "SELECT 'lifecycle',tenant_id,'diagnostic:'||user_id||':'||report_id,expires_at_ms FROM diagnostic_expiry",
    }
    PASSWORD_EXPIRY {
        name: "password_expiry",
        sql: "SELECT user_id,purpose,expires_at FROM password_challenges WHERE expires_at<={now_ms}/1000",
        metrics: "SELECT 'expired_password','','password:'||user_id||':'||purpose,expires_at*1000 FROM password_expiry",
    }
    FEED_EXPIRY {
        name: "feed_expiry",
        sql: "SELECT tenant_id,user_id,id,expires_at_ms FROM feed_sessions WHERE expired=0 AND expires_at_ms<={now_ms}",
        metrics: "SELECT 'lifecycle',tenant_id,'feed:'||user_id||':'||id,expires_at_ms FROM feed_expiry",
    }
    MAINTENANCE {
        name: "maintenance",
        sql: "SELECT j.*,m.task_kind FROM maintenance_tasks m JOIN background_jobs j ON j.tenant_id=m.partition_id AND j.id=m.id WHERE m.enabled=1 AND m.payload_version=1 AND j.work_scope='maintenance' AND j.kind='maintenance'",
        // 正常等待下次周期不算积压；到期或租约失效使用真实调度截止时间。
        metrics: "SELECT 'maintenance',tenant_id,id,CASE WHEN state='running' THEN lease_until_ms ELSE available_at_ms END FROM maintenance WHERE (state='queued' AND available_at_ms<=(SELECT now_ms FROM clock)) OR (state='running' AND lease_until_ms<=(SELECT now_ms FROM clock)) OR state='dead'",
    }
    FENCES {
        name: "fences",
        sql: "SELECT identity_hash FROM identity_unlink_fences WHERE NOT EXISTS(SELECT 1 FROM oidc_attempts WHERE oidc_attempts.sequence<=identity_unlink_fences.sequence)",
        metrics: "SELECT 'expired_oidc','','unlink:'||identity_hash,CAST(NULL AS BIGINT) FROM fences",
    }
}

pub(crate) struct Expiry {
    pub table: &'static str,
    pub key: &'static str,
    pub kind: &'static str,
}
impl Expiry {
    pub fn predicate(&self, cutoff: &str) -> String {
        format!("expires_at<={cutoff}")
    }
}
// 删除入口与采样共享同一张表及到期谓词，级联子表不另作父任务计数。
pub(crate) const OAUTH_EXPIRY: &[Expiry] = &[
    Expiry { table: "oauth_authorization_requests", key: "id", kind: "expired_oauth" },
    Expiry { table: "auth_browser_sessions", key: "hash", kind: "expired_oauth" },
    Expiry { table: "oauth_grants", key: "id", kind: "expired_oauth" },
    Expiry { table: "oauth_clients", key: "id", kind: "expired_oauth" },
];
pub(crate) const IDENTITY_EXPIRY: &[Expiry] = &[
    Expiry { table: "oidc_attempts", key: "id", kind: "expired_oidc" },
    Expiry { table: "oidc_handoffs", key: "hash", kind: "expired_oidc" },
    Expiry { table: "recent_authentication", key: "hash", kind: "expired_oidc" },
    Expiry { table: "identity_events", key: "issuer||':'||event_hash", kind: "expired_oidc" },
];
pub(crate) const SESSIONS: Expiry = Expiry { table: "app_sessions", key: "id", kind: "expired_oidc" };

pub(crate) fn expiry_authorities() -> impl Iterator<Item = &'static Expiry> {
    OAUTH_EXPIRY.iter().chain(IDENTITY_EXPIRY).chain(std::iter::once(&SESSIONS))
}

pub(crate) fn projection(name: &str) -> String {
    // 空候选也携带权威标记；覆盖证据必须来自实际参与快照的联合分支。
    format!("SELECT '{name}',m.* FROM (SELECT 1) seed LEFT JOIN metric_{name} m ON 1=1")
}

pub(crate) fn snapshot_query(clock: &str, api_expiry_ms: &str) -> String {
    let mut ctes = vec![format!("clock AS (SELECT {clock} AS now_ms)")];
    let mut projections = Vec::new();
    for authority in AUTHORITIES {
        ctes.push(format!("{} AS ({})", authority.name, authority.at("(SELECT now_ms FROM clock)")));
        let name = authority.name;
        ctes.push(format!(
            "metric_{name}(kind,tenant_id,id,since_ms) AS ({})",
            authority.metrics.replace("{api_expiry_ms}", api_expiry_ms)
        ));
        projections.push(projection(name));
    }
    for expiry in expiry_authorities() {
        let name = expiry.table;
        ctes.push(format!(
            "expiry_{name} AS (SELECT * FROM {} WHERE {})",
            expiry.table,
            expiry.predicate("(SELECT now_ms/1000 FROM clock)")
        ));
        ctes.push(format!(
            "metric_{name}(kind,tenant_id,id,since_ms) AS (SELECT '{}','','{}:'||{},expires_at*1000 FROM expiry_{name})",
            expiry.kind, expiry.table, expiry.key
        ));
        projections.push(projection(name));
    }
    // 任一来源缺时间都保留 unknown；较早的持久时间是保守起算点，重试和重启不改写。
    format!(
        "WITH {}, candidates(authority,kind,tenant_id,id,since_ms) AS ({}), coverage AS (SELECT authority,COUNT(kind) AS candidates FROM candidates GROUP BY authority), work AS (SELECT kind,tenant_id,id,CASE WHEN COUNT(*)=COUNT(since_ms) THEN MIN(since_ms) END AS since_ms FROM candidates WHERE kind IS NOT NULL GROUP BY kind,tenant_id,id) SELECT clock.now_ms,work.kind,COUNT(work.kind) AS count,COALESCE(SUM(CASE WHEN work.kind IS NOT NULL AND since_ms IS NULL THEN 1 ELSE 0 END),0) AS unknown,COALESCE(SUM(CASE WHEN since_ms>clock.now_ms THEN 1 ELSE 0 END),0) AS future,MIN(CASE WHEN since_ms<=clock.now_ms THEN since_ms END) AS oldest,CAST(NULL AS TEXT) AS authority FROM clock LEFT JOIN work ON 1=1 GROUP BY clock.now_ms,work.kind UNION ALL SELECT clock.now_ms,CAST(NULL AS TEXT),coverage.candidates,0,0,CAST(NULL AS BIGINT),coverage.authority FROM clock CROSS JOIN coverage UNION ALL SELECT clock.now_ms,CAST(NULL AS TEXT),COUNT(*),0,0,CAST(NULL AS BIGINT),'maintenance_state:'||m.task_kind||':'||m.state FROM clock CROSS JOIN maintenance m GROUP BY clock.now_ms,m.task_kind,m.state",
        ctes.join(","),
        projections.join(" UNION ALL ")
    )
}
