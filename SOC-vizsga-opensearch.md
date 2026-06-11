# SOC Vizsga — VPN + Fileserver OpenSearch Help Sheet

## Hozzáférés

| Szolgáltatás | Elérés | Felhasználó | Jelszó |
|---|---|---|---|
| VM konzol | fizikai/VMware | hallgato | hallgato |
| SSH | `ssh hallgato@<VM_IP>` | hallgato | hallgato |
| OpenSearch Dashboards | `http://<VM_IP>:5601` | admin | SOCExam!1234 |

```bash
# IP cím lekérdezése
ip a
# enp0s3 = hálózati elérés (10.x.x.x vagy 192.168.x.x)
# enp0s8 = távoli elérés
```

---

## 0. Előkészületek — állapot ellenőrzése

```bash
sudo systemctl status filebeat
sudo systemctl status logstash
docker ps                        # opensearch-node, opensearch-dashboards, log-generator
ls -l /var/log/exam/             # vpn.log, fileserver.log
tail -5 /var/log/exam/vpn.log
tail -5 /var/log/exam/fileserver.log
```

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

### Config ellenőrzés és indítás

```bash
sudo filebeat test config -e        # Config OK sort kell látni
sudo systemctl start filebeat
sudo systemctl status filebeat
```

**Fontos:** Egyszerre csak egy output lehet aktív — csak `output.logstash` legyen, az `output.elasticsearch` kommentelve!

---

## 2. feladat — Logstash Grok Filter

### Log formátumok

```
# VPN CONNECT:
2026-04-08T12:00:01 vpn-gw01 CONNECT user=jsmith src_ip=85.67.122.10 country=HU status=SUCCESS

# VPN DISCONNECT:
2026-04-08T12:03:00 vpn-gw01 DISCONNECT user=jsmith src_ip=85.67.122.10

# Fileserver:
2026-04-08T12:05:01 fileserver02 user=amiller action=READ file=/projects/roadmap.pdf bytes=24500
```

### Pipeline config írása

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

```
filter {

if [log_type] == "auth" {

grok {

match => { "message" => [

"%{TIMESTAMP_ISO8601:log_timestamp} %{HOSTNAME:hostname} %{WORD:service}: %{DATA: action} for %{USERNAME:user} from %{IP:src_ip} port %{NUMBER:port}",

"%{TIMESTAMP_ISO8601:log_timestamp} %{HOSTNAME:hostname} %{WORD:service}: session %{WORD:session_action} for user %{USERNAME:user}",

"%{TIMESTAMP_ISO8601:log_timestamp} %{HOSTNAME:hostname} %{WORD:service}: %{USERNAME:user} :  {GREEDYDATA:sudo_details}"

]}

}

}

if [log_type] == "access" {

grok {

match => { "message" => "%{COMMONAPACHELOG}" }

}

}

if [log_type] == "firewall" {

grok {

match => { "message" => "%{TIMESTAMP_ISO8601:log_timestamp} %{HOSTNAME:hostname} %

{WORD:action} %{WORD:protocol} %{IP:src_ip} %{IP:dst_ip} %{NUMBER:dst_port} %{NUMBER:src_

port}" }

}

}

}
```


### Logstash indítás és ellenőrzés

```bash
sudo systemctl start logstash
sudo systemctl status logstash
sudo journalctl -u logstash -f      # várj amíg megjelenik: "Pipelines running"
```

**Sikeres indulás jelei:**
- `Pipeline started`
- `Pipelines running {:count=>1}`
- `Starting server on port: 5044`

### Elvárt parseolt mezők

| Log típus | Mezők |
|---|---|
| vpn CONNECT | log_timestamp, gateway, action, user, src_ip, country, status |
| vpn DISCONNECT | log_timestamp, gateway, action, user, src_ip |
| fileserver | log_timestamp, fs_host, user, action, file, bytes |

---

## 3. feladat — Index Pattern és Felderítés

### Index Pattern létrehozása

1. **Dashboards Management** → **Index patterns** → **Create index pattern**
2. Pattern: `vpn-*` → Next → Time field: `@timestamp` → Create
3. Ugyanígy: `fileserver-*` → Next → Time field: `@timestamp` → Create

> Ha a mezőknél felkiáltójelek vannak: Index patterns → válaszd ki → **Refresh field list**

### Hasznos KQL query-k (Discover)

```
# Nem-EU VPN bejelentkezések
NOT country:(HU OR DE OR PL OR SK OR CZ OR AT OR RO OR FR OR GB OR IT OR ES OR NL OR BE OR SE OR NO OR FI OR DK OR CH OR PT OR HR OR RS OR BG OR GR OR UA OR LT OR LV OR EE OR SI)

# Egy felhasználó összes VPN loginja
action:CONNECT AND user:jsmith

# USA-ból sikeres bejelentkezés
country:USA AND status:SUCCESS

# Tömeges letöltés
action:DOWNLOAD AND user:jsmith

# Gyanús felhasználó összes aktivitása fileserveren
user:jsmith
```

### Discover kérdések és válaszok (példa)

| # | Kérdés | Válasz |
|---|---|---|
| 1 | Nem-EU bejelentkezés | **jsmith** — USA |
| 2 | Ország, IP, sikeres? | USA, 45.33.88.12, SUCCESS |
| 3 | Tömeges letöltő | **jsmith** |
| 4 | Mappák/fájlok | /hr/, /finance/, /legal/, /it/ — xlsx, csv, zip, kdbx |
| 5 | Gyanús action | **DOWNLOAD** (normál: READ/LIST/WRITE) |
| 6 | Korreláció | jsmith = VPN USA + tömeges DOWNLOAD → **data exfiltration** |
| 7 | Kiszivárgott adat | ~228 MB (Sum of bytes aggregáció) |

### Aggregáció — bytes összeg (Visualize → Metric)

1. Visualize → Create → **Metric**
2. Index: `fileserver-*`
3. Search: `action:DOWNLOAD AND user:jsmith`
4. Metrics → Aggregation: **Sum** → Field: **bytes**

### Aggregáció — fájlok listája (Visualize → Data Table)

1. Visualize → Create → **Data Table**
2. Index: `fileserver-*`
3. Search: `action:DOWNLOAD AND user:jsmith`
4. Buckets → Split rows → Terms → Field: **file.keyword** → Size: 50

### Aggregáció — country eloszlás (Visualize → Data Table)

1. Visualize → Create → **Data Table**
2. Index: `vpn-*`
3. Buckets → Split rows → Terms → Field: **country.keyword** → Size: 20

---

## 4. feladat — Notification Channel és Alerting

### Notification Channel létrehozása

1. Bal menü → **Notifications** → **Channels** → **Create channel**
2. Channel name: `teams-alert-<sajatneved>`
3. Channel type: **Microsoft Teams**
4. Webhook URL: *(oktatótól kapott URL)*
5. **Create**

### Alert 1 — Non-EU VPN Login

1. Alerting → Monitors → **Create monitor**
2. Monitor name: `Non-EU VPN Login - <sajatneved>`
3. Monitor type: **Per query monitor**
4. Method: **Visual editor**
5. Index: `vpn-*` — Time field: `@timestamp`
6. Time range: **5 minutes**
7. Data filter: `country is USA`
8. Data filter: `status is SUCCESS`
9. Schedule: **Every 2 minutes**
10. Trigger name: `USA Login Detected` — Severity: **1**
11. Trigger condition: **IS ABOVE 0**
12. Action: `Notify Teams` → Channel: `teams-alert-<sajatneved>`
13. **Create**

### Alert 2 — Mass File Download

1. Alerting → Monitors → **Create monitor**
2. Monitor name: `Mass File Download - <sajatneved>`
3. Monitor type: **Per query monitor**
4. Method: **Visual editor**
5. Index: `fileserver-*` — Time field: `@timestamp`
6. Time range: **5 minutes**
7. Data filter: `action is DOWNLOAD`
8. Schedule: **Every 2 minutes**
9. Trigger name: `Mass Download Detected` — Severity: **1**
10. Trigger condition: **IS ABOVE 5**
11. Action: `Notify Teams` → Channel: `teams-alert-<sajatneved>`
12. **Create**

---

## 5. feladat — Dashboard

### Vizualizáció 1 — jsmith kiszivárgott adatmennyiség (Metric)

1. Visualize → **Create new visualization** → **Metric**
2. Index: `fileserver-*`
3. Search: `action:DOWNLOAD AND user:jsmith`
4. Metrics → Sum → bytes
5. Save: `jsmith-exfil-bytes`

### Vizualizáció 2 — VPN bejelentkezések országonként (Pie)

1. Visualize → **Create new visualization** → **Pie**
2. Index: `vpn-*`
3. Buckets → Split slices → Terms → country.keyword → Size: 10
4. Save: `vpn-country-distribution`

### Dashboard összerakása

1. Bal menü → **Dashboard** → **Create new dashboard**
2. Jobb felül → **Add**
3. Add: `jsmith-exfil-bytes`
4. Add: `vpn-country-distribution`
5. Save: `SOC-Dashboard`

---

## Hibakeresés

```bash
# Filebeat logok
sudo journalctl -u filebeat -f

# Logstash logok
sudo journalctl -u logstash -f

# Újraindítás ha szükséges
sudo systemctl restart filebeat
sudo systemctl restart logstash

# Ha semmi nem indexelődik — Filebeat registry törlése (reset)
sudo systemctl stop filebeat
sudo rm -rf /var/lib/filebeat/registry
sudo systemctl start filebeat
```

### Tipikus hibák

| Hiba | Ok | Megoldás |
|---|---|---|
| Filebeat nem indul | Több output aktív | Csak `output.logstash` legyen aktív |
| `_grokparsefailure` tag | Grok pattern nem illeszkedik | `tail` a logra, pattern ellenőrzés |
| Index pattern nem találja az indexet | Filebeat/Logstash nem fut | `systemctl status` ellenőrzés |
| Dashboard "No matching objects" | Rossz tenant | Global tenant-ra váltás |
