# Design

Koyu, "hassas enstrüman" temalı bir güvenlik panosu. Strateji: **Restrained** —
nötr çelik neutraller + anlam taşıyan severity renkleri + tek soğuk marka rengi.

## Theme

Dark. Fiziksel sahne: kullanıcı düşük ışıkta, hızlıca "yeni kritik açık var mı?"
diye bakar. Koyu zemin, severity renklerinin (kırmızı/turuncu/kehribar) parlayıp
gözü çekmesini sağlar. Renk yalnızca anlam için; kroma neutrallerde neredeyse sıfır.

## Color (OKLCH)

Neutraller — soğuk çelik, çok düşük kroma:
- `--bg: oklch(0.155 0.006 225)`      · zemin (neredeyse siyah, çelik ipucu)
- `--surface: oklch(0.190 0.007 225)` · panel/tablo
- `--surface-2: oklch(0.230 0.009 225)`· hover satır / yükseltilmiş
- `--border: oklch(0.285 0.010 225)`  · ayraç
- `--border-strong: oklch(0.360 0.012 225)`
- `--ink: oklch(0.955 0.004 225)`     · gövde metni (≥7:1)
- `--muted: oklch(0.700 0.008 225)`   · ikincil metin (≥3.5:1)
- `--faint: oklch(0.520 0.008 225)`   · üçüncül / pasif

Marka (soğuk çelik-camgöbeği — etkileşim + sağlıklı durum; LACİVERT DEĞİL):
- `--primary: oklch(0.760 0.105 210)`     · link, focus, aktif, metin vurgusu
- `--primary-fill: oklch(0.800 0.100 205)`· birincil buton dolgusu
- `--on-primary: oklch(0.180 0.020 225)`  · dolgu üstü koyu metin

Severity — tehlike gradyanı (SICAK). Blue YOK (marka rengiyle çakışmasın):
- `--sev-crit: oklch(0.660 0.205 25)`   · KRİTİK, kırmızı
- `--sev-high: oklch(0.720 0.165 52)`   · YÜKSEK, turuncu
- `--sev-med: oklch(0.815 0.135 82)`    · ORTA, kehribar
- `--sev-low: oklch(0.660 0.028 235)`   · DÜŞÜK, soğuk gri (düşük ağırlık)
- `--sev-none: oklch(0.600 0.006 225)`  · BİLİNMİYOR, nötr gri

Rozetler: dolgu = ilgili rengin `/0.15` şeffafı, metin = rengin açık tonu.
Yeşil hiçbir yerde yok — "başarılı/aktif" için `--primary` kullanılır.

## Typography

Tek sans ailesi (sistem) + veri için monospace. Sabit rem ölçeği (fluid değil).
- `--font-sans: -apple-system, "SF Pro Text", system-ui, "Segoe UI", sans-serif`
- `--font-mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, monospace`

Ölçek (oran ~1.2): xs .75 / sm .8125 / base .9375 / lg 1.0625 / xl 1.375 rem.
İstatistik sayısı 2rem, `--font-mono`, tabular-nums.
Kanıt verisi (CVE ID, versiyon, port, CPE) her zaman monospace.

## Components

- **Stat kartları**: nötr yüzey, üstte ince severity renkli üst-çizgi (2px, tam
  genişlik — yan-şerit değil), büyük mono sayı, küçük etiket.
- **Tablo**: yoğun (product), satır hover `--surface-2`, focus satırı primary.
- **Badge/pill**: severity ve durum için tek dilli sözlük; tinted bg + renkli metin.
- **Buton**: primary (dolgu+koyu metin), gray (yüzey), red (yıkıcı). Hepsinde
  default/hover/focus/active/disabled.
- **Empty state**: "temiz" ve "tarama yok" ayrı; öğretici, boş değil.

## Motion

150–200ms, yalnızca durum: hover, focus, satır vurgusu. Sayfa yüklenişinde
kartlarda çok hafif, kısa (≤250ms) staggered fade-up — `prefers-reduced-motion`
altında anında görünür. Orkestralı yükleme dizisi yok.

## Layout

Slim üst bar (marka + nav + scheduler durum noktası). İçerik max ~1100px.
Responsive yapısal: dar ekranda kart ızgarası `auto-fit minmax`, tablolar
yatay kaydırılabilir sarmalayıcıda.
