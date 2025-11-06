# File Integrity Monitor

Project ini memantau folder `./secure_files/` untuk mendeteksi file yang:

- Diubah
- Dihapus
- Ditambahkan (unknown file)

Menggunakan hash SHA-256 untuk memverifikasi integritas file. Semua aktivitas dicatat di `security_log.txt`.

## Fitur

1. Monitoring file
   - Simpan baseline hash setiap file (`hash_db.json`).
   - Bandingkan hash saat ini dengan baseline setiap kali scan.
   - Log setiap aktivitas:
     - `INFO` → File aman
     - `WARNING` → File berubah
     - `ALERT` → File baru / dihapus
2. Analisis log
   - Menampilkan jumlah file aman, jumlah file rusak, waktu terakhir ada anomali.
3. Mini Web Interface
   - Menampilkan hasil monitoring secara realtime melalui HTML + JS.
4. Express.js API
   - Endpoint untuk scan file dan membaca log.

---

## Instalasi

1. Clone repo:
```bash
git clone https://github.com/fioreenza/file-monitor.git
cd file-monitor
```

2. Install dependencies:
```bash
npm install express
```

3. Jalankan API
```bash
node server.js
```

4. Buka website interface di browser untuk melihat
- Daftar log file
- Jumlah file aman
- Jumlah file rusak
- Waktu terakhir anomali


## Tech stack
- Node.js
- Express.js
- HTML + JS (mini web interface)
