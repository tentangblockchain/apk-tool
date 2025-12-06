# APK Editor - Replit Setup ✅

## 📋 Ringkasan Proyek
Tool Node.js profesional untuk decompile, analisis, dan modifikasi APK Android dengan fitur-fitur lengkap untuk bypass VIP, unlock episode, dan lainnya.

## 🗂️ Struktur File
- `index.js` - Entry point utama (workflow orchestrator)
- `apk-selector.js` - Module untuk memilih APK dari folder
- `analyzer.js` - Module untuk analisis struktur APK
- `modifier.js` - Module untuk modifikasi APK
- `build-tools.js` - Downloader dan setup apktool + jadx
- `package.json` - Dependencies Node.js
- `.gitignore` - Files yang di-ignore

## 🔧 Tech Stack
- **Node.js v20** ✅
- **System deps**: wget, unzip, openjdk, android-tools
- **APK Tools**: apktool, jadx, keytool, jarsigner

## 📦 Fitur-Fitur Modifikasi

### 1. **Fixed Screen Off** 🔆
- **Tujuan**: Prevent screen dari mati saat user nonton
- **Cara kerja**: Menambahkan WAKE_LOCK permission di AndroidManifest.xml
- **Output**: Layar tetap menyala selama app berjalan

### 2. **VIP / Premium Bypass** 💎
- **Tujuan**: Unlock fitur-fitur VIP/Premium
- **Cara kerja**: Mencari method `isPremium`, `isVIP`, `hasPremium` di smali code dan mengubah return value dari false (0x0) menjadi true (0x1)
- **Pattern**: `const/4 v0, 0x0` → `const/4 v0, 0x1`

### 3. **Membuka Semua Episode** 🎬
- **Tujuan**: Unlock semua episode yang biasanya terkunci
- **Cara kerja**: Mencari method yang handle episode locking dan mengubah logic untuk unlock semua
- **Pattern**: `isLocked`, `unlock`, `isUnlocked` di smali

### 4. **Mendukung Rekam Layar / Screenshot** 🎥
- **Tujuan**: Enable screen recording dan screenshot
- **Cara kerja**: Menambahkan permissions ke AndroidManifest.xml:
  - `WRITE_EXTERNAL_STORAGE`
  - `READ_EXTERNAL_STORAGE`
  - `MEDIA_PROJECTION`

### 5. **Tanpa Login** 🚫
- **Tujuan**: Bypass login screen, akses tanpa login
- **Cara kerja**: Mencari method `isLoggedIn`, `requireLogin`, `checkLogin` dan ubah return value
- **Effect**: App bisa diakses tanpa perlu login

### 6. **Deteksi Dibersihkan** 🧹
- **Tujuan**: Disable detection jika app sudah di-clean/reset
- **Cara kerja**: Disable integrity checks dan cleanup detection methods
- **Pattern**: `isClean`, `cleanup`, `integrity` di smali

### 7. **Perizinan Tidak Penting Telah Dimatikan** 🔐
- **Tujuan**: Remove unnecessary/harmful permissions
- **Cara kerja**: Remove permissions seperti:
  - `INSTALL_PACKAGES`
  - `DELETE_PACKAGES`
  - `CHANGE_COMPONENT_ENABLED_STATE`

### 8. **Bypass Block VPN** 🌐
- **Tujuan**: Bypass VPN detection/block
- **Cara kerja**: Disable VPN detection methods di smali code
- **Pattern**: Cari `VPN`, `vpn`, `proxy`, `Proxy` dan disable check-nya

## 🚀 Cara Menggunakan

### Run Analyzer + Modifier:
```bash
npm start
```

### Workflow:
1. **Setup Tools** - Download apktool dan jadx
2. **Select APK** - Pilih APK dari folder `apk/`
3. **Analyze** - Analisis struktur APK (manifest, strings, smali patterns)
4. **Modify** - Apply semua 8 fitur modifikasi
5. **Recompile** - Compile APK yang sudah dimodifikasi
6. **Sign** - Sign dengan certificate
7. **Output** - `final-signed.apk` siap diinstall

## 📊 Output Files
- `decompiled/` - Folder hasil decompile (akan di-cleanup otomatis)
- `analysis-{timestamp}.json` - Laporan analisis APK
- `modified.apk` - APK hasil recompile (unsigned)
- `final-signed.apk` - **APK final yang signed dan siap install** ✅
- `my-key.keystore` - Certificate untuk signing

## 🎯 Proses Analisis
Script akan melakukan analisis otomatis sebelum modifikasi:

1. **AndroidManifest.xml**: Extract package name, version, permissions, activities, services
2. **strings.xml**: Extract semua string resources dan cari VIP-related strings
3. **Smali Code**: Scan semua .smali files untuk pattern:
   - VIP/Premium checks
   - Episode locks
   - Login methods
   - VPN blocks
   - Cleanup detection

Hasil analisis disimpan di `analysis-{timestamp}.json`

## ⚙️ Konfigurasi

### Pilih APK secara Manual (non-interactive):
Edit `index.js`, ganti:
```javascript
this.selectedAPK = await selector.selectAPKInteractive();
```
Dengan:
```javascript
this.selectedAPK = selector.findAPKByPattern('aplikasi');
```

### Pilih Fitur Mana yang Dimodifikasi:
Edit function `getModificationFeatures()` di `index.js`:
```javascript
getModificationFeatures() {
  return {
    fixScreenOff: true,      // Set false untuk skip
    bypassVIP: true,
    unlockEpisodes: true,
    screenRecording: true,
    bypassLogin: true,
    disableCleanup: true,
    disablePermissions: true,
    bypassVPN: true
  };
}
```

## 📝 Notes & Tips

- ✅ Analyzer melakukan deep scan pada structure sebelum modifikasi
- ✅ Semua modified files tercatat di console dengan detail
- ✅ Support regex patterns untuk find/replace yang lebih powerful
- ✅ Automatic keystore generation jika tidak ada
- ⚠️  Tools di-download otomatis (jadx ~50MB, apktool ~10MB)
- ⚠️  Proses decompile + modify bisa makan waktu 2-5 menit tergantung ukuran APK

## 🛠️ Troubleshooting

**Error: APK not found**
- Pastikan APK ada di folder `apk/`
- Check nama file (case-sensitive)

**Error: Permission denied**
- Run dengan `sudo` jika diperlukan
- Check file permissions di folder apk/

**Pattern not found saat modify**
- Itu normal, berarti app tidak punya pattern tersebut
- Script akan skip ke feature berikutnya

**APK too large**
- Proses decompile lebih lambat untuk APK > 100MB
- Tunggu sampai selesai

## 📚 Dokumentasi Lengkap
Lihat file `analyzer.js`, `modifier.js`, dan `apk-selector.js` untuk dokumentasi inline dan implementasi detail.
