# Secure Exam Distribution Vault — revisi final

Aplikasi Flask untuk **Pusat Pembuat Soal** dan **Pengawas**, dikembangkan dari program awal. Alur soal, dashboard, DB terenkripsi, super enkripsi teks, steganografi, log blockchain, dan berita acara tetap dipertahankan.

## Persiapan di Windows (Python 3.11–3.13)

1. Ekstrak ZIP. Buka terminal **di folder `secure_exam_vault`** (folder berisi `app.py`).
2. Jalankan:

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

3. Buka **http://localhost:5000** lewat Chrome atau Edge. Izinkan akses kamera USB. Tidak memerlukan kamera internal; browser memilih webcam yang terhubung.
4. Akun demo pertama kali: `pusat / Pusat#Vault2026`, `pengawas1 / Pengawas#Vault2026`, `pengawas2 / Pengawas#Vault2026`.
5. **Token dongle tidak lagi dapat diunduh dari halaman login.** Ambil berkas akun masing-masing dari `instance/demo_dongles/<username>.dongle.json`. Serahkan token hanya ke pemilik akun. Token ini simulasi, bukan perangkat USB fisik.

> **Penting:** untuk demonstrasi webcam gunakan `localhost` atau HTTPS agar `getUserMedia` diizinkan. Pastikan pencahayaan terang, hanya satu orang di depan kamera, dan semua izin sistem operasi untuk webcam diaktifkan.

## Alur akun pertama (Pusat maupun Pengawas)

`Username + password awal` → **halaman verifikasi dongle** → **aktivasi webcam (5 frame) dan ganti password awal** → dashboard role. Tidak ada akun yang bisa registrasi sebagai Pusat secara publik.

## Login berikutnya

`Username + password baru` → **halaman verifikasi wajah webcam** → **halaman verifikasi dongle** → dashboard role.

Pusat memiliki menu **Manajemen Pengawas** untuk membuat akun Pengawas. Semua hak akses utama dipertahankan. Pengawas baru menerima token di folder `instance/demo_dongles` (dikirim aman oleh Pusat/admin). Tidak perlu registrasi publik. Akun Pusat pertama dibuat saat seed / CLI.

## Peta ketentuan tugas akhir

| Kriteria | Implementasi | Keterangan |
|---|---|---|
| Login biometric + dongle | `face_auth.py` (OpenCV) + `dongle.py` (HMAC-SHA256 token demo) dan opsi WebAuthn/FIDO2 | **Demo webcam saja tidak anti-spoofing**, dongle virtual bukan USB asli; perlu uji perangkat & persetujuan dosen |
| Login memakai kriptografi | `auth.py`: password PBKDF2-HMAC-SHA256 dengan salt | Dipertahankan |
| Super enkripsi teks | `crypto_core.py`: Vigenère + AES-256-GCM | Dipertahankan |
| Enkripsi file beda dari teks | `file_crypto.py`: ChaCha20-Poly1305 + PBKDF2, header **KGP2** | **KGP1 AES-GCM lama tetap dapat didekripsi** |
| DB data sensitif terenkripsi | `database.py`: AES-256-GCM (termasuk template wajah) | Dipertahankan/diperluas |
| Steganografi gambar | `steganography.py`: LSB PNG | Dipertahankan |
| Blockchain sederhana | `blockchain.py`: hash chain SHA-256 & pemeriksaan integritas | Dipertahankan (bukan blockchain terdistribusi) |

## Catatan keamanan & keterbatasan

- Face recognition OpenCV menggunakan **detektor Haar cascade dan pencocokan histogram Local Binary Pattern (LBP) sederhana**, tidak mencakup pemeriksaan keaslian wajah (*liveness*) yang andal. Foto/video dapat berpotensi menipu sistem. Gunakan **untuk demo perkuliahan saja**, bukan sistem ujian nyata. Akurasi sangat dipengaruhi pencahayaan dan sudut wajah; ambang cocok perlu divalidasi pada perangkat asli.
- Jangan mengeklaim token `.dongle.json` sebagai **USB hardware dongle**. Untuk dongle fisik gunakan FIDO2 security key yang didukung oleh WebAuthn. WebAuthn meminta verifikasi pengguna (UV) namun **UV boleh berupa PIN**, bukan selalu biometrik.
- Kamera merekam frame dalam browser dan dikirim ke aplikasi lokal untuk ekstraksi; yang tersimpan di SQLite adalah **fitur wajah yang dienkripsi AES-GCM**, bukan foto utuh. Template biometrik tetap merupakan data sensitif. Folder `instance` dan file kunci wajib dilindungi, lakukan backup aman.
- **Berita acara, distribusi, stego, blockchain** tetap mengikuti konsep asli. Gambar steganografi dan berkas terenkripsi sama-sama tersedia sesuai akses role; untuk deployment nyata, kunci dekripsi sebaiknya didistribusikan melalui kanal terpisah.
- Password awal demo dicetak pada terminal; **harus diganti saat aktivasi**. Nonaktifkan akun demo di produksi (`KGP_SEED_DEMO=0`), gunakan HTTPS, dan isi `KGP_COOKIE_SECURE=1`.
- Bila pengguna harus ganti atau reset wajah sesudah aktivasi, perlu reset administratif dengan verifikasi identitas; **tidak tersedia reset wajah mandiri dari login** agar tidak bisa diambil alih.

## Pemeriksaan

```powershell
python -m compileall -q .
python test_smoke.py
```

`test_smoke.py` memeriksa alur kriptografi dan aplikasi dengan mock aktivasi biometrik; **bukan** pengujian kamera asli, akurasi wajah, atau USB fisik. Uji langsung di Windows tetap wajib sebelum presentasi.
