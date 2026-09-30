# Product

## Register

product

## Users

Güvenlik alanında kendini geliştiren biri ve küçük ekipler; kendi test
ortamlarındaki (kendi sunucuları, VM'ler, izinli test host'ları) sistemleri
zafiyetlere karşı otomatik ve periyodik izlemek isteyenler. Kullanıcı çoğunlukla
"bugün yeni bir kritik açık çıktı mı, hangi hedef risk altında?" sorusuyla panoya
bakar — genellikle düşük ışıklı bir ortamda, hızlı tarama yaparak.

## Product Purpose

Hedefleri nmap ile tarar, servis versiyonlarını NVD (CVE) veritabanıyla
eşleştirir, sonuçları periyodik olarak biriktirir. Bu arayüz o birikimi
insan gözüyle **izlenebilir ve önceliklendirilebilir** kılar. Başarı:
kullanıcı panoya bakınca en tehlikeli bulguyu saniyeler içinde görür ve
hangi hedefe önce müdahale edeceğini bilir.

## Brand Personality

Sakin, kesin, güvenilir. Bir Hollywood "hacker ekranı" değil, iyi kalibre
edilmiş bir ölçüm aleti. Üç kelime: **hassas, sessiz, otoriter.**

## Anti-references

- Neon yeşil "terminal/hacker" panoları (Mr. Robot estetiği).
- Lacivert + altın fintech dashboard'ları.
- Gereksiz glow/parlama efektleri, glassmorphism "SOC duvarı" gösterisi.
- Anlam taşımayan dekoratif renk; her yeri renklendiren gradyanlar.
- **Yeşil ve lacivert kullanılmaz** (kullanıcı kısıtı + renk körlüğü erişilebilirliği).

## Design Principles

1. **Gösteri değil sinyal** — göz önce en yüksek severity'ye gitmeli. Renk
   tehlike demektir, dekorasyon değil.
2. **Enstrüman, pano-tiyatrosu değil** — sessiz kesinlik; bir ölçüm aleti güveni.
3. **Kanıt okunabilirliği** — versiyon, CVE ID, port ve CPE birer kanıttır;
   monospace ile net gösterilir.
4. **Kazanılmış aşinalık** — standart ürün kalıpları; araç göreve karışır,
   kendini göstermez.
5. **Dürüst durumlar** — "temiz", "tarama yok", "başarısız", "çalışıyor" her biri
   ayrı ve açık anlatılır; temiz bir hedef boş ekran değil, iyi haberdir.

## Accessibility & Inclusion

WCAG AA hedefi; gövde metni bg'ye karşı ≥7:1. Severity asla yalnızca renkle
kodlanmaz — her zaman metin etiketi eşlik eder. Yeşilden kaçınmak kırmızı-yeşil
renk körlüğü riskini de azaltır. Tüm animasyonlar `prefers-reduced-motion`
altında crossfade/anlık geçişe düşer. Odak (focus) halkaları her etkileşimli
öğede görünür.
