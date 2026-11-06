import os
import sys
import dongle

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    pakai_serial = "--tanpa-serial" not in sys.argv
    timpa = "--timpa" in sys.argv

    if args:
        lokasi = args[0]
    else:
        pilihan = dongle.lokasi_drive()
        if not pilihan:
            print("Tidak ada flashdisk terdeteksi.")
            return 1
        print("Flashdisk terdeteksi:")
        for i, p in enumerate(pilihan, 1):
            print("  %d. %s" % (i, p))
        jawab = input("Pilih nomor flashdisk yang dijadikan donggle: ").strip()
        if not jawab.isdigit() or not (1 <= int(jawab) <= len(pilihan)):
            print("Pilihan tidak valid.")
            return 1
        lokasi = pilihan[int(jawab) - 1]

    if not os.path.isdir(lokasi):
        print("Lokasi tidak ditemukan.")
        return 1

    try:
        h, serial = dongle.daftarkan(lokasi, pakai_serial)
    except (RuntimeError, OSError) as e:
        print("Gagal membuat donggle: %s" % e)
        return 1

    print("\nDongle berhasil dibuat di %s" % lokasi)
    return 0

if __name__ == "__main__":
    sys.exit(main())