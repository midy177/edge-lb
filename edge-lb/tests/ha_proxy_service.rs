//! Production API/SQLite/replication processes, without BFD or datapath changes.
use reqwest::{Method, blocking::Client};
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement, TransactionTrait};
use serde_json::{Value, json};
use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ADMIN: &str = "integration-admin-only";
const SESSION: &str = "integration-peer-only";

struct Node {
    dir: PathBuf,
    name: String,
    ip: String,
    url: String,
    index: u8,
    child: Option<Child>,
    client: Client,
}

impl Node {
    fn new(name: &str, index: u8) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("edge-ha-{name}-{}-{nonce}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let ip = format!("192.0.2.{}", index + 10);
        fs::write(
            dir.join("config.toml"),
            format!(
                r#"
node_role = "gateway"
node_name = "{name}"
public_ip = "{ip}"
underlay_ip = "{ip}"
state_dir = "{}"
log_level = "warn"
[gateway.network]
underlay_dev = "lo"
vxlan_dev = "edge-test-hub"
overlay_cidr = "10.200.{index}.0/24"
vxlan_mtu = 1450
dscp = {}
[gateway.api]
listen = "{addr}"
auth_token = "{ADMIN}"
trusted_source_cidrs = ["127.0.0.0/8"]
"#,
                dir.display(),
                index + 40
            ),
        )
        .unwrap();
        Self {
            dir,
            name: name.into(),
            ip,
            url: format!("http://{addr}"),
            index,
            child: None,
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
        }
    }

    fn start(&mut self) {
        assert!(self.child.is_none());
        let log = fs::File::create(self.dir.join("process.log")).unwrap();
        self.child = Some(
            Command::new(env!("CARGO_BIN_EXE_edge-lb"))
                .args([
                    "--config",
                    self.dir.join("config.toml").to_str().unwrap(),
                    "ui",
                    "serve",
                ])
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(exit) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!(
                    "{} exited {exit}: {}",
                    self.name,
                    fs::read_to_string(self.dir.join("process.log")).unwrap()
                );
            }
            if self
                .client
                .get(format!("{}/api/v1/ha/proxy-config-sync", self.url))
                .bearer_auth(ADMIN)
                .send()
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{} did not become ready",
                self.name
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            child.wait().unwrap();
        }
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = self.client.request(method, format!("{}{path}", self.url));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().unwrap();
        let status = response.status().as_u16();
        let text = response.text().unwrap();
        let body =
            serde_json::from_str(&text).unwrap_or_else(|_| panic!("{path}: HTTP {status}: {text}"));
        (status, body)
    }

    fn get(&self, path: &str) -> Value {
        let (status, body) = self.request(Method::GET, path, Some(ADMIN), None);
        assert_eq!(status, 200, "{body}");
        body
    }

    fn write(&self, method: Method, path: &str, body: Value, authority: &str) -> Value {
        let (status, body) = self.request(method, path, Some(ADMIN), Some(body));
        assert_eq!(status, 202, "{body}");
        assert_eq!(body["sync"]["authority_committed"], true);
        assert_eq!(body["sync"]["replica_confirmed"], false);
        assert_eq!(body["sync"]["authority"], authority);
        assert!(body["sync"]["barrier"]["sequence"].as_u64().unwrap() > 0);
        body
    }

    // Only seed control metadata while the process is stopped. All business
    // mutations and replica delivery below use the production HTTP APIs.
    fn configure_pair(&self, peer: &Self, active: &str, token: &str, pairing_id: &str) {
        assert!(self.child.is_none());
        let documents = [
            (
                "ha",
                "config",
                json!({"enabled":true,"self_index": self.index,"peers":[{
                    "name":peer.name,"underlay_ip":peer.ip,"api_addr":peer.url,
                    "overlay_cidr":format!("10.200.{}.0/24",peer.index),
                    "overlay_ip":format!("10.200.{}.1/24",peer.index),"dscp":peer.index+40
                }]})
                .to_string(),
            ),
            (
                "ha_peer_secret",
                "config",
                json!({"peer_name":peer.name,"peer_underlay_ip":peer.ip,
                "session_token":token,"session_token_id":pairing_id})
                .to_string(),
            ),
            ("ha_active_gateway", "current", active.to_string()),
        ];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let db = Database::connect(format!("sqlite://{}?mode=rw",self.dir.join("edge-lb.sqlite3").display())).await.unwrap();
            let tx = db.begin().await.unwrap();
            let row = tx.query_one(Statement::from_string(DatabaseBackend::Sqlite,
                "SELECT COALESCE(MAX(revision), 0) AS revision FROM config_revisions")).await.unwrap().unwrap();
            let mut revision: i64 = row.try_get("", "revision").unwrap();
            for (kind, name, payload) in documents {
                revision += 1;
                tx.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
                    "INSERT INTO config_revisions (revision, content_hash, source_node, committed_at) VALUES (?, 'fixture', 'fixture', 'fixture')", [revision.into()])).await.unwrap();
                tx.execute(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
                    "INSERT INTO resource_documents (resource_type, resource_name, revision, payload, updated_at) VALUES (?, ?, ?, ?, 'fixture') ON CONFLICT(resource_type, resource_name) DO UPDATE SET revision=excluded.revision,payload=excluded.payload",
                    [kind.into(),name.into(),revision.into(),payload.into()])).await.unwrap();
            }
            tx.commit().await.unwrap();
            db.close().await.unwrap();
        });
    }

    fn document(&self, kind: &str) -> Value {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let db = Database::connect(format!("sqlite://{}?mode=ro",self.dir.join("edge-lb.sqlite3").display())).await.unwrap();
            let row = db.query_one(Statement::from_sql_and_values(DatabaseBackend::Sqlite,
                "SELECT payload FROM resource_documents WHERE resource_type=? AND resource_name='config'", [kind.into()])).await.unwrap().unwrap();
            let payload: String = row.try_get("", "payload").unwrap();
            db.close().await.unwrap();
            serde_json::from_str(&payload).unwrap()
        })
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !check() {
        assert!(
            Instant::now() < deadline,
            "HA state did not converge within 15 seconds"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_synced(a: &Node, b: &Node) {
    wait_until(|| {
        let left = a.get("/api/v1/ha/proxy-config-sync");
        let right = b.get("/api/v1/ha/proxy-config-sync");
        left["pending"] == false
            && right["pending"] == false
            && left["source"] == a.name
            && ["sequence", "source", "pairing_id", "content_hash"]
                .iter()
                .all(|key| left[key] == right[key])
    });
    assert_eq!(a.document("listeners"), b.document("listeners"));
    assert_eq!(a.document("target_groups"), b.document("target_groups"));
}

#[test]
fn production_ha_api_retries_after_process_restart_and_fences_roles_and_tokens() {
    let mut a = Node::new("gateway-a", 0);
    let mut b = Node::new("gateway-b", 1);
    // Production initialization creates the schema; no copied test schema.
    a.start();
    b.start();
    a.stop();
    b.stop();
    a.configure_pair(&b, &a.name, SESSION, "pair-1");
    b.configure_pair(&a, &a.name, SESSION, "pair-1");
    a.start();
    a.write(
        Method::POST,
        "/api/v1/target-groups",
        json!({"name":"web","targets":[],"monitor":false}),
        &a.name,
    );
    let accepted = a.write(
        Method::POST,
        "/api/v1/listener-configs",
        json!({
            "vip_ips":[],"port":80,"target_port":8080,"protocols":["tcp","udp"],
            "target_group":"web","select":"hash","inactive_timeout":60
        }),
        &a.name,
    );
    wait_until(|| a.get("/api/v1/ha/proxy-config-sync")["last_error"].is_string());
    let before = a.get("/api/v1/ha/proxy-config-sync");
    assert_eq!(before["pending"], true);
    a.stop();
    a.start();
    let after = a.get("/api/v1/ha/proxy-config-sync");
    assert_eq!(before["sequence"], after["sequence"]);
    assert_eq!(before["content_hash"], after["content_hash"]);
    assert_eq!(after["pending"], true);
    b.start();
    wait_synced(&a, &b);
    assert_eq!(b.get("/api/v1/listener-configs")[0]["name"], "tcp-udp-80");
    assert!(
        b.get("/api/v1/ha/proxy-config-sync")["sequence"]
            .as_u64()
            .unwrap()
            >= accepted["sync"]["barrier"]["sequence"].as_u64().unwrap()
    );

    b.write(
        Method::POST,
        "/api/v1/target-groups",
        json!({"name":"other","targets":[],"monitor":false}),
        &a.name,
    );
    wait_synced(&a, &b);
    assert_eq!(b.document("target_groups").as_array().unwrap().len(), 2);
    b.write(
        Method::PUT,
        "/api/v1/listener-configs/tcp-udp-80",
        json!({"vip_ips":[],"port":80,"target_port":8080,"protocols":["tcp","udp"],
            "target_group":"web","select":"hash","inactive_timeout":120}),
        &a.name,
    );
    wait_synced(&a, &b);
    assert_eq!(b.document("listeners")[0]["inactive_timeout"], 120);
    let state = a.get("/api/v1/ha/proxy-config-sync");
    let snapshot = json!({"sequence":state["sequence"],"source":state["source"],
        "pairing_id":state["pairing_id"],"content_hash":state["content_hash"],
        "config":{"listeners":a.document("listeners"),"target_groups":a.document("target_groups")}});

    for token in [None, Some(ADMIN), Some("invalid-peer")] {
        assert_eq!(
            b.request(
                Method::POST,
                "/api/v1/ha/peer/proxy-config/replica",
                token,
                Some(snapshot.clone())
            )
            .0,
            401
        );
    }
    assert_eq!(
        b.request(
            Method::GET,
            "/api/v1/ha/proxy-config-sync",
            Some(SESSION),
            None
        )
        .0,
        401
    );
    assert_eq!(
        b.request(
            Method::POST,
            "/api/v1/ha/peer/proxy-config/replica",
            Some(SESSION),
            Some(snapshot.clone())
        )
        .0,
        200
    );
    let mut stale = snapshot.clone();
    stale["sequence"] = json!(state["sequence"].as_u64().unwrap() - 1);
    assert_eq!(
        b.request(
            Method::POST,
            "/api/v1/ha/peer/proxy-config/replica",
            Some(SESSION),
            Some(stale)
        )
        .0,
        409
    );
    assert_eq!(
        b.get("/api/v1/ha/proxy-config-sync")["content_hash"],
        state["content_hash"]
    );

    a.stop();
    b.stop();
    a.configure_pair(&b, &b.name, "rotated-peer-only", "pair-2");
    b.configure_pair(&a, &b.name, "rotated-peer-only", "pair-2");
    a.start();
    b.start();
    wait_synced(&b, &a);
    assert_eq!(
        a.request(
            Method::POST,
            "/api/v1/ha/peer/proxy-config/replica",
            Some(SESSION),
            Some(snapshot.clone())
        )
        .0,
        401
    );
    // A current token does not authorize an old pairing or a write on MASTER's replica endpoint.
    assert_eq!(
        a.request(
            Method::POST,
            "/api/v1/ha/peer/proxy-config/replica",
            Some("rotated-peer-only"),
            Some(snapshot.clone())
        )
        .0,
        409
    );
    assert_eq!(
        b.request(
            Method::POST,
            "/api/v1/ha/peer/proxy-config/replica",
            Some("rotated-peer-only"),
            Some(snapshot)
        )
        .0,
        409
    );
    let op = json!({"kind":"target_group_delete","name":"other"});
    assert_eq!(
        a.request(
            Method::POST,
            "/api/v1/ha/peer/proxy-config/active",
            Some("rotated-peer-only"),
            Some(op)
        )
        .0,
        409
    );
    a.write(
        Method::POST,
        "/api/v1/target-groups",
        json!({"name":"after-promotion","targets":[],"monitor":false}),
        &b.name,
    );
    wait_synced(&b, &a);
    assert_eq!(a.document("target_groups").as_array().unwrap().len(), 3);
    a.write(
        Method::DELETE,
        "/api/v1/listener-configs/tcp-udp-80",
        Value::Null,
        &b.name,
    );
    wait_synced(&b, &a);
    assert_eq!(a.get("/api/v1/listener-configs"), json!([]));
    a.write(
        Method::DELETE,
        "/api/v1/target-groups/web",
        Value::Null,
        &b.name,
    );
    wait_synced(&b, &a);
    assert_eq!(a.document("target_groups").as_array().unwrap().len(), 2);
}
