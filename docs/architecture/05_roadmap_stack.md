# FortiCheck — ADIM 9 & 10: MVP Yol Haritası ve Teknoloji Stack

---

## ADIM 9 — MVP YOL HARİTASI

### Faz 1 — Temel Analiz (MVP Core) — 4-6 Hafta

**Hedef:** Tek bir FortiGate config dosyasını parse edip temel güvenlik bulgularını üretmek.

| Bileşen | Kapsam |
|---|---|
| FortiGate Parser | `config` / `edit` / `set` blok parse, VDOM desteği |
| Object Resolver | Address, addrgrp, service, service group recursive çözme |
| Policy Normalizer | Canonical PolicyRule modeline dönüşüm |
| Zone Mapper | Interface → Zone mapping, trust level ataması |
| Basic Analysis | `any/any/any` tespiti, disabled rule tespiti, security profile eksikliği |
| Shadow Detection | Full shadow rule tespiti (temel algoritma) |
| CLI | `forticheck analyze --config fw.conf --output report.html` |
| HTML Report | Executive summary, kritik bulgular, temel heatmap |

**Çıktı:** Çalışan CLI aracı + temel HTML rapor

---

### Faz 2 — Graph Modelleme — 3-4 Hafta

**Hedef:** Network topolojisini graph olarak modellemek ve zone-bazlı analiz yapmak.

| Bileşen | Kapsam |
|---|---|
| Topology Graph | Interface, subnet, zone node'ları, route edge'leri |
| Policy Graph | Policy edge'leri, zone-pair mapping |
| Trust Boundary Analyzer | Zone trust delta hesaplama, ihlal tespiti |
| East-West Analyzer | İç zone'lar arası exposure matrisi |
| Internet Exposure | WAN→Internal policy tespiti, VIP/DNAT çözme |
| Redundancy Detection | Kaldırılabilir kurallar (tam algoritma) |
| Enhanced Report | Zone heatmap, exposure tabloları, segmentasyon analizi |

**Çıktı:** Graph-aware analiz + gelişmiş rapor

---

### Faz 3 — Attack Path Simülasyonu — 3-4 Hafta

**Hedef:** Multi-hop saldırı yollarını simüle etmek ve risk skorlama.

| Bileşen | Kapsam |
|---|---|
| Attack Path Engine | BFS/DFS path enumeration, trust gradient filtering |
| Pivot Detection | Multi-zone erişimli subnet tespiti |
| Risk Scorer | 5-faktörlü composite skor hesaplama |
| Risk Aggregator | Cihaz/zone bazlı aggregate skor |
| Path Visualization | Attack chain diyagramları raporda |
| Remediation Engine | Bulgu bazlı otomatik öneri üretimi |
| Enhanced Report | Attack path diyagramları, risk gauge, remediation önerileri |

**Çıktı:** Tam analiz suite + skorlanmış profesyonel rapor

---

### Faz 4 — Gelişmiş Özellikler — Sürekli

**Hedef:** Ölçeklenebilirlik, multi-vendor, karşılaştırma.

| Bileşen | Kapsam |
|---|---|
| Config Diff | İki config arasındaki policy değişiklik analizi |
| Multi-vendor Parser | Palo Alto, Cisco ASA parser eklentileri |
| Batch Analysis | Çoklu cihaz toplu analiz, merkezi rapor |
| API Server | REST API (MSSP entegrasyonu için) |
| SIEM Entegrasyonu | JSON finding export (Splunk, ELK, Wazuh) |
| Scheduled Scan | Periyodik config analizi (CI/CD pipeline) |
| Custom Rules | Kullanıcı tanımlı analiz kuralları (YAML DSL) |
| Web Dashboard | İnteraktif web arayüzü (opsiyonel) |

---

## ADIM 10 — TEKNOLOJİ STACK

### Backend

| Katman | Teknoloji | Gerekçe |
|---|---|---|
| Dil | **Python 3.11+** | Hızlı geliştirme, zengin kütüphane ekosistemi, güvenlik topluluğunda standart |
| CLI Framework | **Click** veya **Typer** | Profesyonel CLI deneyimi, otomatik help |
| Config Management | **Pydantic** | Tip güvenliği, veri doğrulama, canonical model tanımı |
| Async (Faz 4) | **asyncio** | Batch analiz, API server |
| API (Faz 4) | **FastAPI** | REST API, otomatik OpenAPI doc |

### Analiz Motoru

| Katman | Teknoloji | Gerekçe |
|---|---|---|
| IP Matematik | **netaddr** veya **ipaddress** (stdlib) | CIDR hesaplama, subnet overlap, IP set operations |
| Veri Yapıları | **dataclasses** + **Pydantic** | Canonical model tanımı |
| Interval Tree | **intervaltree** | Port range overlap tespiti (shadow/redundancy) |
| Set Operations | **Özel IP Range Set** | Policy küme karşılaştırmaları için optimized data structure |

### Graph Motoru

| Katman | Teknoloji | Gerekçe |
|---|---|---|
| Graph Kütüphanesi | **NetworkX** | Hafif, pure Python, BFS/DFS built-in, kurulumu kolay |
| Gelişmiş (Faz 4) | **igraph** veya **graph-tool** | Büyük graph performansı (binlerce policy) |
| Visualizasyon | **Mermaid** veya **D3.js** (rapor içi) | HTML raporda interaktif graph |

### Raporlama Motoru

| Katman | Teknoloji | Gerekçe |
|---|---|---|
| Template Engine | **Jinja2** | Güçlü şablonlama, blok inheritance, makrolar |
| Grafikler | **Chart.js** (inline) | Heatmap, gauge, bar chart — JS bağımlılığı yok (CDN-free embed) |
| Stil | **Özel CSS** | Self-contained tek HTML dosya garantisi |
| PDF (opsiyonel) | **WeasyPrint** veya **Playwright** | HTML → PDF dönüşümü |

### Proje Altyapısı

| Alan | Teknoloji |
|---|---|
| Paket Yönetimi | **Poetry** veya **uv** |
| Test | **pytest** + fixture'lar |
| Linting | **ruff** |
| Type Checking | **mypy** |
| CI/CD | **GitHub Actions** |
| Dokümantasyon | **MkDocs** (opsiyonel) |

### Bağımlılık Özeti (Faz 1 için minimal)

```
# pyproject.toml - MVP dependencies
[tool.poetry.dependencies]
python = "^3.11"
click = "^8.1"           # CLI
pydantic = "^2.5"        # Data models
netaddr = "^0.9"         # IP mathematics
networkx = "^3.2"        # Graph
jinja2 = "^3.1"          # HTML templates
rich = "^13.7"           # Terminal output
pyyaml = "^6.0"          # Zone trust config

[tool.poetry.group.dev.dependencies]
pytest = "^7.4"
ruff = "^0.1"
mypy = "^1.7"
```

> [!TIP]
> Faz 1 sadece 7 production bağımlılık ile çalışır. Bu minimal footprint, hızlı dağıtım ve güvenlik açısından önemlidir.

### Mimari Kararlar Özeti

| Karar | Seçim | Alternatif | Gerekçe |
|---|---|---|---|
| Tek dosya dağıtım | CLI tool (pip install) | Docker | SOC/pentester'lar için kurulum kolaylığı |
| Graph kütüphanesi | NetworkX | Neo4j, JanusGraph | Offline analiz, veritabanı gereksiz |
| Rapor formatı | Self-contained HTML | PDF, DOCX | Tarayıcıda açılır, paylaşımı kolay, interaktif |
| Veri modeli | Pydantic | SQLAlchemy | Veritabanı gereksiz, tip güvenliği |
| Config parse | Custom parser | TextFSM, TTP | FortiOS'a özel optimizasyon |
