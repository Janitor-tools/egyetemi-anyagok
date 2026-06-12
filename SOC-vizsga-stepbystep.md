# SOC Vizsga — Teljes megoldás lépésről lépésre
**Szabados József – TCE40Y**

---

## 0. Előkészületek

```bash
# IP cím lekérdezése
ip a
# enp0s3 = hálózati elérés

# Állapot ellenőrzés
sudo systemctl status filebeat
sudo systemctl status logstash
docker ps
ls -l /var/log/exam/

# Log formátumok megnézése
tail -5 /var/log/exam/vpn.log
tail -5 /var/log/exam/fileserver.log
```

**OpenSearch Dashboards elérése:** `http://<VM_IP>:5601`
- User: `admin` / Jelszó: `SOCExam!1234`
- Első megnyitáskor: **Global** tenant választása

---

## 1. feladat — Filebeat konfiguráció

```bash
sudo tee /etc/filebeat/filebeat.yml > /dev/null << 'EOF'
filebeat.inputs:

- type: log
  enabled: true
  paths:
    - /var/log/exam/vpn.log
  fields:
    log_type: vpn
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/exam/fileserver.log
  fields:
    log_type: fileserver
  fields_under_root: true

output.logstash:
  hosts: ["localhost:5044"]

seccomp.enabled: false
EOF
```

```bash
# Config ellenőrzés — "Config OK" sort kell látni
sudo filebeat test config -e

# Indítás
sudo systemctl start filebeat
sudo systemctl status filebeat
```

---

## 2. feladat — Logstash Grok Filter

```bash
sudo tee /opt/logstash/config/conf.d/pipeline.conf > /dev/null << 'EOF'
input {
  beats {
    port => 5044
  }
}
filter {
  if [log_type] == "vpn" {
    grok {
      match => { "message" => [
        "%{TIMESTAMP_ISO8601:log_timestamp} %{HOSTNAME:gateway} %{WORD:action} user=%{WORD:user} src_ip=%{IP:src_ip} country=%{WORD:country} status=%{WORD:status}",
        "%{TIMESTAMP_ISO8601:log_timestamp} %{HOSTNAME:gateway} %{WORD:action} user=%{WORD:user} src_ip=%{IP:src_ip}"
      ] }
    }
  }
  if [log_type] == "fileserver" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:log_timestamp} %{HOSTNAME:fs_host} user=%{WORD:user} action=%{WORD:action} file=%{UNIXPATH:file} bytes=%{NUMBER:bytes:int}" }
    }
  }
}
output {
  opensearch {
    hosts => ["https://localhost:9200"]
    user => "admin"
    password => "SOCExam!1234"
    ssl_certificate_verification => false
    index => "%{log_type}-%{+YYYY.MM.dd}"
    manage_template => false
  }
}
EOF
```

```bash
# Indítás
sudo systemctl start logstash

# Ellenőrzés — várj amíg megjelenik: "Pipelines running"
sudo journalctl -u logstash -f
# Kilépés: Ctrl+C
```

---

## 3. feladat — Index Pattern és Felderítés

### Index Pattern létrehozása

1. OpenSearch Dashboards → bal alul **Management** (fogaskerék)
2. **Index Patterns** → **Create index pattern**
3. Pattern: `vpn-*` → Next → Time field: `@timestamp` → **Create**
4. Ugyanígy: `fileserver-*` → Next → Time field: `@timestamp` → **Create**

### Discover — kérdések megválaszolása

Bal menü → **Discover** → index pattern váltás bal felül

**Hasznos query-k:**
```
# Nem-EU bejelentkezések
NOT country:(HU OR DE OR PL OR SK OR CZ OR AT OR RO OR FR OR GB OR IT OR ES OR NL OR BE OR SE OR NO OR FI OR DK OR CH OR PT OR HR)

# USA-ból sikeres bejelentkezés
country:USA AND status:SUCCESS

# Egy felhasználó összes VPN loginja
action:CONNECT AND user:jsmith

# Tömeges letöltések
action:DOWNLOAD AND user:jsmith
```

### Aggregációk (Visualize)

**Fájlok listája — Data Table:**
1. Visualize → Create → **Data Table** → `fileserver-*`
2. Search: `action:DOWNLOAD AND user:jsmith`
3. Buckets → Split rows → Terms → `file.keyword` → Size: 50
4. Play gomb

**Kiszivárgott bytes — Metric:**
1. Visualize → Create → **Metric** → `fileserver-*`
2. Search: `action:DOWNLOAD AND user:jsmith`
3. Metrics → Aggregation: **Sum** → Field: **bytes**
4. Play gomb → **Save** → `jsmith-exfil-bytes`

**VPN country eloszlás — Pie chart:**
1. Visualize → Create → **Pie** → `vpn-*`
2. Buckets → Split slices → Terms → `country.keyword` → Size: 10
3. Play gomb → **Save** → `vpn-country-distribution`

### Kérdések és válaszok

| # | Kérdés | Válasz |
|---|---|---|
| 1 | Nem-EU bejelentkezés | **jsmith** — USA |
| 2 | Ország, IP, sikeres? | USA, 45.33.88.12, **SUCCESS** |
| 3 | Tömeges letöltő | **jsmith** |
| 4 | Mappák/fájlok | `/hr/`, `/finance/`, `/legal/`, `/it/` — xlsx, csv, zip, kdbx |
| 5 | Gyanús action | **DOWNLOAD** (normál: READ/LIST/WRITE) |
| 6 | Korreláció | jsmith = USA VPN + tömeges DOWNLOAD → **data exfiltration** |
| 7 | Kiszivárgott adat | **~228 MB** (Sum of bytes) |

---

## 4. feladat — Notification Channel és Alerting

### Notification Channel létrehozása

1. Bal menü → **Notifications** → **Channels** → **Create channel**
2. Channel name: `teams-alert-<sajatneved>`
3. Channel type: **Microsoft Teams**
4. Webhook URL: *(oktatótól kapott URL)*
5. **Create**

### Alert 1 — Non-EU VPN Login

1. Bal menü → **Alerting** → **Monitors** → **Create monitor**
2. Monitor name: `Non-EU VPN Login - <sajatneved>`
3. Monitor type: **Per query monitor**
4. Monitor defining method: **Visual editor**
5. Index: `vpn-*` — Time field: `@timestamp`
6. Time range for the last: **5 minutes**
7. Metrics: Count (marad)
8. **Add filter**: `country` · is · `USA`
9. **Add filter**: `status` · is · `SUCCESS`
10. Schedule: **Every 2 minutes**
11. **Add trigger** → Trigger name: `USA Login Detected` → Severity: **1**
12. Trigger condition: **IS ABOVE 0**
13. **Add action** → Action name: `Notify Teams` → Channel: `teams-alert-<sajatneved>`
14. **Create**

### Alert 2 — Mass File Download

1. Alerting → Monitors → **Create monitor**
2. Monitor name: `Mass File Download - <sajatneved>`
3. Monitor type: **Per query monitor**
4. Monitor defining method: **Visual editor**
5. Index: `fileserver-*` — Time field: `@timestamp`
6. Time range for the last: **5 minutes**
7. Metrics: Count (marad)
8. **Add filter**: `action` · is · `DOWNLOAD`
9. Schedule: **Every 2 minutes**
10. **Add trigger** → Trigger name: `Mass Download Detected` → Severity: **1**
11. Trigger condition: **IS ABOVE 5**
12. **Add action** → Action name: `Notify Teams` → Channel: `teams-alert-<sajatneved>`
13. **Create**

### Alert ellenőrzés

Alerting → Monitors listában ellenőrizd:
- **State**: Enabled ✅
- **Active**: 1 ✅ (triggerelt)
- **Errors**: 0 ✅

---

## 5. feladat — Dashboard

1. Bal menü → **Dashboard** → **Create new dashboard**
2. Jobb felül → **Add**
3. Keress rá: `jsmith-exfil-bytes` → hozzáadás
4. Keress rá: `vpn-country-distribution` → hozzáadás
5. **Save** → `SOC-Dashboard`

---

## Hibakeresés

```bash
# Ha Filebeat nem indul
sudo journalctl -u filebeat -f

# Ha Logstash nem indul
sudo journalctl -u logstash -f

# Ha semmi nem indexelődik — registry törlés
sudo systemctl stop filebeat
sudo rm -rf /var/lib/filebeat/registry
sudo systemctl start filebeat

# Újraindítás
sudo systemctl restart filebeat
sudo systemctl restart logstash
```

| Hiba | Ok | Megoldás |
|---|---|---|
| Filebeat nem indul | Több output aktív | Csak `output.logstash` legyen aktív |
| `_grokparsefailure` | Grok pattern nem illeszkedik | `tail` a logra, pattern javítás |
| Index pattern nem találja az indexet | Filebeat/Logstash nem fut | `systemctl status` ellenőrzés |
| Dashboard "No matching objects" | Rossz tenant | Global tenant-ra váltás |
| Teams alert nem megy | Network unreachable | Monitor triggerelt-e? (Active: 1 elég) |
