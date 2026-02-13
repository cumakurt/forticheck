# Next-Generation Firewall Security Analysis Platform
## Security Intent & Network Behavior Architecture

**Document Type:** Strategic Architecture Analysis  
**Author:** Principal Security Architect  
**Scope:** FortiGate configuration analysis — beyond traditional policy validation  

---

## BÖLÜM 1 — GELENEKSEL ANALİZİN SINIRLARI

### Klasik Firewall Analiz Araçlarının Yaptıkları

| Analiz Türü | Ne Yapar | Çıktı |
|-------------|----------|-------|
| **Policy Risk** | Policy bazlı risk skorlama (any/any, geniş servisler, profil eksikliği) | Tekil policy risk skoru |
| **Shadow Rule** | Üstteki policy tarafından gölgelenen kuralların tespiti | Gölgelenen policy listesi |
| **Segmentation Check** | Zone/policy kesişimlerinin kontrolü | Segmentasyon ihlalleri |
| **Exposure** | Düşük güvenlikli zone'dan yüksek güvenliğe erişim tespiti | Trust boundary ihlalleri |

### Neden Yetersiz?

1. **Statik Snapshot:** Sadece "ne izin verilmiş" sorusuna cevap verir. "Bu izin güvenlik niyetine hizmet ediyor mu?" sorusuna cevap veremez.

2. **Tek Policy Odaklı:** Policy'ler zincir halinde değil, izole analiz edilir. Transit erişim (A→B→C) ve dolaylı erişim modellenmez.

3. **Gizli Güven İlişkileri:** VPN, same-zone, management interface gibi config'te policy olarak görünmeyen güven kanalları tespit edilmez.

4. **Davranış Değil, Konfigürasyon:** Gerçek ağ davranışı ile tanımlanan mimari arasındaki sapma ölçülmez.

5. **Blast Radius Eksikliği:** "Bir varlık ele geçirilirse ne kadar yayılabilir?" sorusu cevapsız kalır.

6. **İş-Bağlamı Yok:** Teknik olarak doğru ama iş amacına uygun olmayan erişimler ayırt edilemez.

---

## BÖLÜM 2 — YENİ NESİL ANALİZ VİZYONU

### Temel Paradigma Kayması

```
Geleneksel: "Firewall ne yapıyor?"
Yeni Nesil: "Firewall güvenlik amacını sağlıyor mu?"
```

### Vizyon Açıklaması

Platform, firewall'u **konfigürasyon nesnesi** değil, **güvenlik mimarisinin uygulayıcısı** olarak ele alır. Amaç:

- **Intent Alignment:** Tanımlanan güvenlik amacı ile gerçek erişim desenleri uyumlu mu?
- **Architectural Integrity:** Zone, trust boundary, segmentation tasarımı korunuyor mu?
- **Attack Surface Comprehension:** Ele geçirilebilecek her noktadan saldırı genişlemesi ne kadar?
- **Implicit Risk Visibility:** Config'te açıkça yazılmamış ancak var olan güven kanalları nerede?

### Hedef Kullanıcı Kararı

CISO, mimar veya güvenlik ekibi şu soruyu yanıtlamalı:

> "Bu firewall konfigürasyonu, organizasyonun güvenlik stratejisini destekliyor mu, yoksa stratejiyi baltalıyor mu?"

---

## BÖLÜM 3 — SECURITY INTENT ANALYSIS

### Tanımlanmış Erişim Amacı vs Gerçek Erişim Davranışı

**Soru:** Tanımlanan erişim amacı ile gerçek erişim davranışı uyumlu mu?

### Analiz Yeteneği

| Bileşen | Açıklama |
|--------|----------|
| **Intent Source** | Policy comments, zone trust level tanımları, naming convention, iş katmanı metadata (opsiyonel) |
| **Behavior Source** | Policy matrisi, resolved address/service grupları, NAT kuralları, routing |
| **Comparison** | Intent ile behavior'ın çakışma veya fazlalık noktaları |

### Örnek Sapmalar

- **Over-permission:** "Sadece web sunucularına" denilmiş, gerçekte tüm DMZ erişilebilir.
- **Under-permission:** İş gereksinimi var ama policy eksik — tespit edilmesi zor, ama intent ile karşılaştırıldığında anomalı davranış işareti olabilir.
- **Scope Creep:** Başlangıçta tek servis için açılmış policy, zamanla "ALL" servise genişlemiş.

### Model

```
Intent = f(comments, zone_design, naming, external_metadata)
Behavior = f(policy_rules, resolved_objects, nat, routing)
Gap = |Intent ∩ Behavior| vs |Intent| vs |Behavior|
```

---

## BÖLÜM 4 — IMPLICIT TRUST DISCOVERY

### Görünmeyen Güven İlişkileri

Config'te explicit policy olarak görünmeyen, ancak gerçekte güven ilişkisi oluşturan yapılar.

### Analiz Motoru Bileşenleri

| Trust Türü | Tespit Yöntemi | Risk |
|------------|----------------|------|
| **Same-Zone Trust** | Aynı zone içindeki interfaceler arası trafik; zone içi policy varsayımları | Zone ayrımı etkisiz; lateral movement kolay |
| **VPN Implicit Access** | VPN split-tunnel, route inject, phase2 selectors — VPN üzerinden hangi subnet'lere erişilebilir | Uzaktan iç ağa geniş erişim |
| **Management Trust Leakage** | Management interface ACL, allowaccess (https, ssh, ping, fgfm), trusted host | Mgmt arayüzü saldırı başlangıç noktası |

### Engine Çıktıları

- Implicit trust grafi (policy grafiğine ek kenarlar)
- Trust leakage score: Gizli güven kanallarının sayısı ve hassasiyetine göre
- Same-zone exposure matrisi

---

## BÖLÜM 5 — BLAST RADIUS ANALİZİ

### Temel Soru

**Compromise sonrası erişim genişliği nedir?**

Bir varlık (IP, zone, segment) ele geçirildiğinde, saldırgan kaç hedefe, hangi servislerle, kaç hop ile ulaşabilir?

### Analiz Modeli

```
BlastRadius(v) = ReachableNodes(v) × SensitiveServices × TrustGain
```

- **ReachableNodes(v):** v'den policy grafiği üzerinden erişilebilen tüm zone/network node'ları (BFS/DFS).
- **SensitiveServices:** RDP, SMB, SSH, DB portları gibi hassas servislerin ağırlığı.
- **TrustGain:** Başlangıç trust'ından hedef trust'a geçiş miktarı.

### Çıktılar

- **Per-entity blast radius:** Her zone/segment için "ele geçirilirse X zone'a, Y servise erişilebilir".
- **Blast radius heatmap:** Hangi compromise noktaları en geniş yayılıma yol açıyor?
- **Critical pivot points:** Ele geçirildiğinde en çok erişim sağlayan node'lar.

---

## BÖLÜM 6 — SEGMENTATION DRIFT ANALİZİ

### Tanımlanan Segmentasyon vs Gerçek Erişim

**Soru:** Firewall segmentasyonu etkisiz hale getiriyor mu?

### Analiz Motoru

| Girdi | Açıklama |
|-------|----------|
| **Defined Segmentation** | Zone tasarımı, trust level'lar, segment sınırları (varsa) |
| **Actual Access** | Policy matrisi + transitive closure → gerçek zone-to-zone erişim |
| **Drift** | Tanımlanan ayrım ile gerçek erişim arasındaki fark |

### Örnek Drift Senaryoları

- **Effective Any-to-Any:** Farklı zone'larda olmalarına rağmen, policy zinciri ile tüm zone'lar birbirine bağlı.
- **Trust Inversion:** Düşük trust zone, yüksek trust zone'dan daha fazla hedefe erişebiliyor.
- **Shadow Segmentation:** "DMZ izole" denilmiş ama DMZ→LAN, LAN→DMZ policy'leri mevcut.

### Metrik

```
SegmentationEffectiveness = 1 - (|ActualAccess| / |AllPossibleAccess|)
Drift = |DefinedBoundaries - ActualBoundaries|
```

---

## BÖLÜM 7 — POLICY BEHAVIOR ANALYSIS

### Policy Zinciri ve Transit Erişim

Policy tek başına değil, **zincir halinde** analiz edilir.

### Sorular

- Transit erişim oluşuyor mu? (A→B policy, B→C policy ⇒ A→C mümkün?)
- Policy chaining sonucu dolaylı erişim var mı?

### Davranış Analizi Modeli

```
PolicyGraph = (Zones, Policies as directed edges)
TransitiveClosure = Graph.Reachability()
TransitPaths = Paths where intermediate zone != source and != destination
```

### Çıktılar

- **Transit path listesi:** Hangi zone çiftleri doğrudan policy olmadan, ara zone üzerinden erişilebilir?
- **Policy chain depth:** En uzun zincir kaç hop?
- **Unintended bridge:** İki izole segment beklenirken, bir policy zinciri ile birleşmiş mi?

---

## BÖLÜM 8 — TRUST BOUNDARY MISMATCH

### Network Trust Seviyeleri vs Gerçek Erişimler

**Soru:** Prod, Dev, Mgmt sınırları korunuyor mu?

### Analiz Motoru

| Bileşen | Açıklama |
|---------|----------|
| **Trust Levels** | Zone trust (0–100), interface role (wan/lan/dmz), naming convention |
| **Expected Boundaries** | Prod↔Dev, Prod↔Mgmt, Dev↔Mgmt geçişlerinin yasak/controllu olması |
| **Actual Flow** | Policy grafiğinden gerçek zone-to-zone trafik |

### Mismatch Türleri

- **Prod–Dev leakage:** Production zone'dan Development zone'a veya tersi izinli erişim.
- **Mgmt exposure:** Management zone'dan iş zone'larına veya iş zone'larından management'a doğrudan erişim.
- **Trust inversion:** Düşük trust zone'dan yüksek trust zone'a izin, tasarımda olmaması gereken akış.

### Metrik

```
MismatchCount = |{ (src,dst) : Allowed(src,dst) AND ShouldBeBlocked(src,dst) }|
```

---

## BÖLÜM 9 — LATERAL MOVEMENT LIKELIHOOD

### Bir Kullanıcı veya Sistem Ele Geçirilirse: Yatay İlerleme İhtimali

### Hesaplama Modeli

```
LateralMovementLikelihood(entry_point) =
  α × ReachableHighValueTargets(entry_point) +
  β × SensitiveServiceExposure(entry_point) +
  γ × ChainDepth(entry_point) +
  δ × SameZoneSpread(entry_point)
```

| Faktör | Açıklama |
|--------|----------|
| **ReachableHighValueTargets** | Entry point'ten erişilebilen yüksek trust zone sayısı |
| **SensitiveServiceExposure** | RDP, SMB, SSH, DB gibi servislerin varlığı |
| **ChainDepth** | Ortalama kaç policy atlaması ile hedefe ulaşılabiliyor |
| **SameZoneSpread** | Aynı zone içinde kaç cihaz var (implicit trust) |

### Çıktı

- Entry point başına lateral movement skoru (0–100).
- En riskli entry point'ler listesi.
- "Bu zone ele geçirilirse, ortalama X adımda Y hassas zone'a ulaşılabilir" özeti.

---

## BÖLÜM 10 — HIDDEN TRANSITIVE ACCESS

### Dolaylı Erişim Modeli

```
A → B  (policy allows)
B → C  (policy allows)
⇒ A → C mümkün mü? (transitive)
```

### Analiz Modeli

1. **Directed Graph:** Zone'lar node, policy'ler edge.
2. **Transitive Closure:** Tüm (src, dst) çiftleri için reachability hesaplama.
3. **Direct vs Transitive Ayrımı:** Doğrudan policy ile A→C yok, ama B üzerinden var mı?

### Çıktılar

- **Transitive-only access listesi:** Sadece zincir üzerinden erişilebilen zone çiftleri.
- **Hidden path matrix:** Hangi (src,dst) çiftlerinin sadece dolaylı erişimi var?
- **Bridge policies:** Hangi policy'ler kritik "köprü" görevi görüyor?

---

## BÖLÜM 11 — POLICY COMPLEXITY RISK

### Config Karmaşıklığı → Güvenlik Riski

| Risk Türü | Tanım | Etki |
|------------|------|------|
| **Overlap** | Policy'lerin adres/servis/zone açısından örtüşmesi | Hangi policy'nin ne zaman devreye girdiği belirsiz; revizyon riski |
| **Reuse** | Aynı address/service group'un çok sayıda policy'de kullanılması | Tek değişiklik geniş etki; yanlış değişiklik blast radius |
| **Policy Sprawl** | Çok sayıda policy, benzer amaçlar için | Operasyonel hata, gölgeleme, bakım zorluğu |

### Analiz Modeli

- **Overlap Index:** Her policy çifti için overlap skoru (intersection/union).
- **Reuse Factor:** Her object için kaç policy'de referans var.
- **Sprawl Score:** Policy sayısı / beklenen minimal policy sayısı (tahmini).

### Çıktı

- Complexity risk skoru (0–100).
- En karmaşık policy/object'ler.
- "Bu object değiştirilirse X policy etkilenir" uyarıları.

---

## BÖLÜM 12 — BUSINESS ALIGNMENT ANALYSIS

### Firewall Erişimleri İş İhtiyacı ile Uyumlu mu?

**Hedef:** Teknik olarak doğru ama iş açısından yanlış erişimleri tespit.

### Model Zorluğu

Firewall config'te iş amacı genelde **metadata** olarak bulunmaz. Çıkarım gerekir:

- **Naming convention:** Policy/adres isimlerinden iş bağlamı (ör. "HR-to-Finance", "DMZ-Web")
- **Zone design:** Zone isimleri (prod, dev, guest, partner)
- **External input:** Opsiyonel olarak iş erişim matrisi (kim kime erişebilmeli) harici dosyadan yüklenebilir

### Analiz Yaklaşımı

1. **Heuristic:** Zone/prod-dev-mgmt ayrımı ile "Dev'den Prod'a erişim olmamalı" gibi kurallar.
2. **Anomaly:** Benzer policy'ler arasında beklenmedik farklılıklar.
3. **Intent from comments:** Policy comment'lerinden amacın çıkarılması ve davranışla karşılaştırılması.

### Çıktılar

- İş kuralı ihlalleri (örn. "Prod–Dev karışımı").
- Olası yanlış konfigürasyonlar ("Guest zone'dan internal DB'ye erişim").
- İş–teknik uyumsuzluk özeti.

---

## BÖLÜM 13 — ANALİZ MOTORLARI

### Motor Envanteri

| Motor | Sorumluluk | Girdi | Çıktı |
|-------|------------|-------|-------|
| **Intent Analysis Engine** | Tanımlanan amaç ile gerçek erişim uyumu | Config, metadata, comments | Intent–behavior gap raporu |
| **Implicit Trust Engine** | Gizli güven kanalları | Zones, interfaces, VPN config, mgmt ACL | Implicit trust grafi, leakage skoru |
| **Blast Radius Engine** | Compromise sonrası yayılım | Policy grafiği, trust levels, servis hassasiyeti | Per-entity blast radius, heatmap |
| **Segmentation Drift Engine** | Tanımlanan vs gerçek segmentasyon | Zone design, policy matrisi, transitive closure | Drift skoru, etkisiz segmentasyon listesi |
| **Behavior Chain Engine** | Policy zinciri, transit erişim | Policy grafiği | Transit path listesi, chain depth |
| **Trust Boundary Engine** | Prod/Dev/Mgmt sınırları | Trust levels, policy flow | Mismatch listesi |
| **Lateral Movement Engine** | Yatay ilerleme ihtimali | Entry points, reachability, sensitive servisler | Likelihood skoru, riskli entry'ler |
| **Transitive Access Engine** | Dolaylı erişim | Policy grafiği, transitive closure | Hidden path matrisi, bridge policy'ler |

### Motor Bağımlılıkları

```
Policy Graph (canonical)
    ├── Behavior Chain Engine
    ├── Transitive Access Engine
    ├── Blast Radius Engine
    └── Lateral Movement Engine

Zone/Trust Model
    ├── Trust Boundary Engine
    ├── Segmentation Drift Engine
    └── Implicit Trust Engine

Intent Metadata (optional)
    └── Intent Analysis Engine
```

---

## BÖLÜM 14 — RİSK SKORLAMA

### Tek Güvenlik Skoru Modeli

Tüm analizleri **tek composite skor** ve **alt skorlara** dönüştürme:

```
CompositeSecurityScore = Σ (Weight_i × NormalizedScore_i)
```

### Önerilen Ağırlıklar (örnek)

| Alt Skor | Ağırlık | Kaynak Motor(lar) |
|----------|---------|-------------------|
| Blast Radius Exposure | 0.20 | Blast Radius Engine |
| Lateral Movement Risk | 0.18 | Lateral Movement Engine |
| Segmentation Drift | 0.15 | Segmentation Drift Engine |
| Trust Boundary Mismatch | 0.15 | Trust Boundary Engine |
| Implicit Trust Leakage | 0.12 | Implicit Trust Engine |
| Transitive Access Risk | 0.10 | Transitive Access Engine |
| Policy Complexity | 0.05 | Policy Complexity (mevcut) |
| Intent–Behavior Gap | 0.05 | Intent Analysis Engine |

### Normalizasyon

- Her motor 0–100 skor üretir.
- Yüksek skor = yüksek risk.
- Composite: 0–100, yorum: 0–25 Low, 26–50 Medium, 51–75 High, 76–100 Critical.

---

## BÖLÜM 15 — RAPOR ÇIKTISI

### Üretilecek İçgörü Kategorileri

| Kategori | Örnek Mesaj | İlgili Motor(lar) |
|----------|-------------|-------------------|
| **Mimari Uyumsuzluk** | "Firewall mimari amaca hizmet etmiyor" | Intent Analysis, Trust Boundary, Segmentation Drift |
| **Segmentasyon Zayıflığı** | "Segmentasyon etkisiz; zone'lar fiilen birleşik" | Segmentation Drift, Behavior Chain |
| **Gizli Güven** | "Gizli güven ilişkileri mevcut (VPN, same-zone, mgmt)" | Implicit Trust Engine |
| **Saldırı Genişlemesi** | "Saldırı genişleme potansiyeli yüksek; X noktası ele geçirilirse Y zone'lara erişim" | Blast Radius, Lateral Movement, Transitive Access |
| **Sınır İhlalleri** | "Prod–Dev sınırı ihlal edilmiş" | Trust Boundary Engine |
| **Dolaylı Tehdit** | "Doğrudan policy yok ama A→C transit erişim var" | Transitive Access, Behavior Chain |
| **Karmaşıklık Riski** | "Policy sprawl ve overlap operasyonel risk oluşturuyor" | Policy Complexity |

### Özet Dashboard Önerisi

1. **Executive:** Composite skor, en kritik 3–5 içgörü.
2. **Architectural:** Mimari uyumsuzluklar, segmentasyon etkinliği.
3. **Attack Surface:** Blast radius, lateral movement, kritik pivot noktaları.
4. **Trust:** Implicit trust, trust boundary mismatch.
5. **Operational:** Policy karmaşıklığı, önerilen iyileştirmeler.

---

## ÖZET — ODAK ALANLARI

| Odak | Açıklama |
|------|----------|
| **Güvenlik Davranışı** | Policy'nin ne dediği değil, bunun gerçek ağ davranışına nasıl yansıdığı |
| **Mimari Analiz** | Zone, trust, segmentasyon tasarımının config'te korunup korunmadığı |
| **Saldırı Yayılımı** | Bir compromise noktasından ne kadar yayılım mümkün |
| **Güven İlişkileri** | Explicit ve implicit güven kanallarının tam haritası |

---

*Bu doküman, FortiCheck platformunun yeni nesil analiz vizyonu için stratejik mimari referans sağlar.*
