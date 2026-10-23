# PRIMA — Pertamina Checklist Mobil Tangki

Aplikasi checklist mobil tangki berbasis Laravel (backend) dan React (frontend).

- Pengembangan lokal: `docker compose up -d --build`, lalu buka http://localhost:8091
- Produksi: image diambil dari GHCR, lihat `compose.production.yaml`

## CI/CD

Setiap push ke `main` menjalankan test backend, build frontend, dan validasi
Docker Compose. Jika seluruh CI sukses, workflow release akan:

1. membangun image backend dan frontend;
2. menerbitkannya ke GHCR dengan tag commit yang immutable;
3. terhubung ke server production melalui SSH;
4. menjalankan `git pull --ff-only`, menarik image baru, dan mengganti container.

Konfigurasikan GitHub Environment bernama `production` dengan secrets berikut:

- `PROD_SSH_HOST`: domain atau IP server;
- `PROD_SSH_PORT`: port SSH (opsional, default `22`);
- `PROD_SSH_USER`: user deployment di server;
- `PROD_SSH_PRIVATE_KEY`: private key SSH khusus GitHub Actions;
- `PROD_SSH_KNOWN_HOSTS`: hasil `ssh-keyscan -H <host>` yang sudah diverifikasi.

Tambahkan environment variable `PROD_DEPLOY_PATH` berisi direktori checkout repo
di server, misalnya `/opt/prima`. Direktori tersebut harus memiliki `.env`
production, remote Git yang dapat diakses, serta akses untuk menjalankan Docker.
Jika package GHCR bersifat private, login satu kali di server menggunakan akun
atau token yang memiliki izin `read:packages`.

Perubahan lokal baru masuk pipeline setelah di-commit dan di-push ke `main`.
