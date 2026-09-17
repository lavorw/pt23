# Analisis Log Serangan — Portrait Studio Web Defacement

**File log**: `portrait_access.log` (format Apache combined log)
**Total baris**: 15.635
**IP Server korban**: `10.233.6.67:8080`
**Referensi**: ARTIFACT BIMTEK PUSSIBER v1.0 — Blue Team Scenario: Web Defacement

Dokumen ini berisi seluruh command yang dijalankan untuk melakukan investigasi log, beserta penjelasan tujuan tiap command dan apa yang ditemukan darinya.

---

## 0. Persiapan

### Cek keberadaan file log & PDF skenario
```bash
find /home/ping/claude -maxdepth 3 -iname "*.log" -o -iname "*.pdf" 2>/dev/null
```
**Tujuan**: memastikan lokasi file log dan dokumen skenario Bimtek sebelum memulai analisis.

### Cek jumlah baris dan format log
```bash
wc -l /home/ping/claude/portrait_access.log
head -5 /home/ping/claude/portrait_access.log
tail -5 /home/ping/claude/portrait_access.log
```
**Tujuan**: memverifikasi jumlah baris log (harus 15.635 sesuai PDF) dan mengenali format Apache combined log:
```
<IP> - - [tanggal:jam +0000] "METHOD path HTTP/1.1" status size "referer" "user-agent"
```
**Catatan penting**: dari `tail`, ditemukan bahwa urutan baris di file **tidak selalu berurutan berdasarkan waktu** (ada baris IP `.72` jam 13:13 diikuti baris IP `.71` jam 13:04). Ini berarti log perlu **di-sort ulang berdasarkan timestamp** sebelum membuat timeline.

### Cek rentang tanggal dalam log
```bash
awk -F'[][]' '{print $2}' /home/ping/claude/portrait_access.log | cut -d: -f1 | sort -u
```
**Tujuan**: memastikan seluruh log berada di tanggal yang sama (16/Sep/2026), sehingga sorting berdasarkan jam saja sudah cukup akurat tanpa perlu menangani perbedaan bulan/tahun.

---

## 1. Identifikasi IP Attacker

### Hitung jumlah request per IP
```bash
awk '{print $1}' /home/ping/claude/portrait_access.log | sort | uniq -c
```
**Tujuan**: melihat distribusi trafik per IP. IP dengan jumlah request yang jauh lebih besar dari yang lain biasanya adalah pelaku automated scanning/brute force.

**Hasil**:
| IP | Jumlah Request | Kategori |
|---|---|---|
| 10.233.6.66 | 18 | Normal visitor |
| 10.233.6.71 | **15.548** | **Attacker** |
| 10.233.6.72 | 38 | Normal visitor |
| ::1 | 31 | Local (health check) |

---

## 2. Ekstraksi & Pengurutan Log Attacker

### Ekstrak semua baris milik attacker
```bash
grep '^10.233.6.71 ' /home/ping/claude/portrait_access.log > attacker_raw.log
wc -l attacker_raw.log
```
**Tujuan**: memisahkan trafik attacker dari trafik normal agar analisis lebih fokus.

### Urutkan berdasarkan timestamp
```bash
awk -F'[][]' '{print $2, $0}' attacker_raw.log | \
  sed -E 's/^([0-9]+)\/([A-Za-z]+)\/([0-9]+):([0-9:]+) \+0000 /\3-\2-\1T\4 /' > attacker_sortkey.log

sort -k1,1 attacker_sortkey.log | cut -d' ' -f2- > attacker_sorted.log

head -1 attacker_sorted.log   # aktivitas pertama
tail -1 attacker_sorted.log   # aktivitas terakhir
```
**Tujuan**: mengubah format tanggal `[16/Sep/2026:12:08:07` menjadi format yang bisa di-sort leksikografis (`2026-Sep-16T12:08:07`), lalu mengurutkan seluruh baris attacker secara kronologis. Ini penting supaya timeline serangan yang disusun benar-benar sesuai urutan waktu kejadian, bukan urutan fisik di file.

**Hasil**: aktivitas pertama attacker terekam pada **16/Sep/2026 12:08:07 UTC**.

---

## 3. Identifikasi User-Agent Attacker

```bash
awk -F'"' '{print $6}' attacker_sorted.log | sort | uniq -c | sort -rn
```
**Tujuan**: field ke-6 (dipisah tanda kutip `"`) pada Apache combined log adalah User-Agent. Menghitung kemunculannya membantu mengenali apakah attacker memakai browser manual atau tools otomatis.

**Hasil**: ditemukan 2 User-Agent berbeda:
- `Firefox/155.0` (121 request) → dipakai untuk browsing manual (recon awal & aktivitas pasca-eksploitasi)
- `Chrome/87.0.4280.88 Safari/537.36` (15.427 request) → UA default tools brute force otomatis (mis. dirsearch/ffuf/gobuster)

### Cari titik pergantian UA
```bash
grep -n "Chrome/87" attacker_sorted.log | head -3
grep -n "Firefox/155" attacker_sorted.log | tail -5
```
**Tujuan**: menentukan kapan attacker beralih dari browsing manual ke tool otomatis, dan kapan kembali ke aktivitas manual (indikasi pergantian fase serangan).

---

## 4. Analisis Directory Brute Force

### Breakdown status code selama fase brute force
```bash
grep "Chrome/87" attacker_sorted.log | awk '{print $9}' | sort | uniq -c | sort -rn
```
**Tujuan**: kolom ke-9 adalah HTTP status code. Mayoritas `404` menandakan scanning wordlist (banyak path yang tidak ada), sedangkan `200/301/302/403` adalah endpoint yang benar-benar ditemukan/valid.

### Lihat endpoint yang berhasil ditemukan (bukan 404)
```bash
grep "Chrome/87" attacker_sorted.log | awk '$9!=404 {print $9, $7}' | sort | uniq -c | sort -rn

grep "Chrome/87" attacker_sorted.log | awk '$9==200 {print $4, $9, $7}'
grep "Chrome/87" attacker_sorted.log | awk '$9==301 {print $4, $9, $7}'
grep "Chrome/87" attacker_sorted.log | awk '$9==302 {print $4, $9, $7}'
grep "Chrome/87" attacker_sorted.log | awk '$9==400 {print $4, $9, $7}'
```
**Tujuan**: `$4` adalah timestamp, `$7` adalah path yang diakses. Memfilter per status code membantu memisahkan endpoint sungguhan (login, dashboard, uploads, dll.) dari noise hasil scanning.

**Hasil endpoint ditemukan**: `/administrator`, `/administrator.php`, `/dashboard`, `/db.php`, `/index.php`, `/index.php/login/`, `/logout`, `/profile`, `/assets` (301), `/uploads` (301).

### Hitung rentang waktu & rate request (bukti automated scanning)
```bash
grep "Chrome/87" attacker_sorted.log | head -1 | awk '{print $4}'
grep "Chrome/87" attacker_sorted.log | tail -1 | awk '{print $4}'

grep "Chrome/87" attacker_sorted.log | awk -F'[][]' '{print $2}' | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -10
```
**Tujuan**: mengukur berapa lama fase brute force berlangsung dan berapa request per detik. Angka request/detik yang sangat tinggi (puncak ~150 req/detik, total 15.427 request dalam ~4 menit 20 detik) adalah ciri khas tool otomatis, bukan manusia yang mengetik manual.

---

## 5. Analisis SQL Injection & Login Bypass

### Lihat semua request POST yang dikirim attacker
```bash
grep '"POST' attacker_sorted.log | awk '{print $4, $6, $7, $9}' | sort | uniq -c | sort -rn
```
**Tujuan**: melihat endpoint mana yang menerima POST (form submission) dari attacker — di sini terlihat mayoritas ke `/administrator` (form login).

### Ambil semua variasi request line POST /administrator
```bash
grep '"POST /administrator' attacker_sorted.log | \
  sed -E 's/^.*\] "(.*)" [0-9]+ [0-9]+ .*$/\1/' | sort -u
```
**Tujuan**: melihat apakah ada payload SQL injection yang terekam di URL/query string. Ditemukan satu request dengan parameter `loFe` berisi payload `UNION ALL SELECT ... xp_cmdshell` — indikasi scanner otomatis mencoba payload generik SQLi/RCE/XSS.

### Lihat urutan status code POST /administrator secara kronologis
```bash
grep '"POST /administrator' attacker_sorted.log | awk '{print $4, $9}' | sed 's/\[//'
```
**Tujuan**: karena Apache access log **tidak mencatat isi body POST**, payload SQLi yang sebenarnya (dikirim lewat form login) tidak bisa dibaca langsung dari log. Namun pola request bisa disimpulkan dari kombinasi:
- Jumlah request (85 request) dalam waktu sangat singkat (~90 detik) → indikasi fuzzing otomatis (mis. sqlmap).
- Status `500` berulang → payload SQL merusak query (syntax error di database).
- Status `200` → percobaan gagal normal (kembali ke halaman login).
- Status `302` → **login berhasil** (redirect setelah autentikasi sukses).

### Ambil timestamp login berhasil
```bash
grep '"POST /administrator' attacker_sorted.log | grep ' 302 '
```
**Tujuan**: mengisolasi baris dengan status `302` untuk menentukan waktu pasti attacker berhasil bypass login. Ditemukan dua momen: **12:36:17** (pertama) dan **12:36:59** (konfirmasi ulang).

---

## 6. Analisis Aktivitas Pasca-Login (Upload & Webshell)

### Lihat semua aktivitas tepat setelah login berhasil
```bash
sed -n '/12:36:17/,/12:40:00/p' attacker_sorted.log | grep -v 404
```
**Tujuan**: `sed -n '/pattern1/,/pattern2/p'` mencetak semua baris di antara dua pola (rentang waktu tertentu). `grep -v 404` membuang noise request gagal. Dari sini terlihat attacker mengakses `/dashboard` lalu `/profile`.

### Lihat detail proses upload file berbahaya
```bash
sed -n '/12:45:55/,/12:47:35/p' attacker_sorted.log
```
**Tujuan**: menelusuri jendela waktu di sekitar fitur `/profile` untuk menemukan momen upload webshell. Ditemukan:
- `POST /profile` (12:45:55 & 12:46:38) → upload file lewat fitur profile/avatar.
- `GET /uploads/halodunia.php` (12:46:47, status 500) → percobaan akses pertama.
- `GET /uploads/halodunia.php?cmd=id` (12:46:55, status 200) → **command execution berhasil**, membuktikan file yang diupload adalah webshell PHP dan tersimpan langsung bisa diakses dari `/uploads/`.

### Ekstrak seluruh command yang dijalankan lewat webshell
```bash
grep 'halodunia.php?cmd=' attacker_sorted.log | \
  sed -E 's/^.*cmd=([^ ]*) HTTP.*$/\1/' | uniq -c

grep -c 'halodunia.php?cmd=' attacker_sorted.log
```
**Tujuan**: mengambil hanya nilai parameter `cmd=` dari tiap request untuk merekonstruksi command apa saja yang dijalankan attacker di server, secara berurutan (`id`, `whoami`, `pwd`, `cat /etc/passwd`, `ls -la`, `wget ...`, `mv ...`).

---

## 7. Kesimpulan Timeline (hasil akhir dari seluruh command di atas)

| Waktu (UTC) | Kejadian |
|---|---|
| 12:08:07 | Recon awal (browsing manual, Firefox UA) |
| 12:08:38 – 12:12:58 | Directory brute force otomatis (15.427 request, Chrome/87 UA) |
| 12:31:27 | Percobaan login manual pertama |
| 12:35:02 – 12:36:19 | Fuzzing SQL Injection pada `POST /administrator` (85 request) |
| **12:36:17** | **Login bypass berhasil** (302) |
| 12:36:59 | Login dikonfirmasi ulang (302) |
| 12:45:55 – 12:46:38 | Upload webshell `halodunia.php` lewat `POST /profile` |
| **12:46:55** | **Command execution pertama berhasil** (`?cmd=id`) |
| 12:47:01 – 13:03:45 | Enumerasi sistem + staging payload kedua (`shinobijakarta.zip` → `.php`) |
| 13:04:04 | Akses pertama ke shell kedua `shinobijakarta.php` |
| **13:27:23** | **Website berhasil di-deface** (`hacked.gif` + homepage berubah) |

**Catatan**: aktivitas privilege escalation (`env /bin/sh -p`) dan penambahan user root di `/etc/passwd` **tidak tercatat di log HTTP ini** karena dilakukan lewat shell interaktif di level OS, bukan lewat request web — sesuai catatan di PDF bahwa analisis lebih lanjut untuk Post-Exploitation Activity perlu sumber log lain (mis. `auth.log`, bash history).
