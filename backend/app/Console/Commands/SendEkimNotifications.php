<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;

class SendEkimNotifications extends Command
{
    protected $signature = 'prima:notifications {--dry-run : Periksa kandidat tanpa mengirim email atau mengubah database}';

    protected $description = 'Kirim notifikasi email EKIM yang mendekati atau melewati masa berlaku';

    public function handle(): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $settings = DB::table('system_settings')->pluck('setting_value', 'setting_key');
        $days = max(0, min(365, (int) ($settings['notif_days_threshold'] ?? 30)));
        $until = today()->addDays($days)->toDateString();
        $rows = DB::table('formulir_checklist as f')
            ->join('kendaraan as k', 'k.nomor_polisi', '=', 'f.nomor_polisi')
            ->where('f.status_approval', 'approved')
            ->whereNotNull('k.email_kontraktor')
            ->whereRaw("TRIM(k.email_kontraktor) <> ''")
            ->whereNotNull('f.ekim_valid_until')
            ->where('f.ekim_valid_until', '<=', $until)
            ->whereRaw('f.id=(SELECT MAX(f2.id) FROM formulir_checklist f2 WHERE f2.nomor_polisi=f.nomor_polisi AND f2.status_approval=?)', ['approved'])
            ->select('f.*', 'k.email_kontraktor')
            ->get();

        if ($dryRun) {
            $this->info('Mode uji: '.$rows->count().' kandidat ditemukan; tidak ada email atau data yang diubah.');

            return self::SUCCESS;
        }

        if (! $this->smtpReady($settings)) {
            $message = 'SMTP belum lengkap. Isi host, port, dan email pengirim; jika memakai akun SMTP, isi juga passwordnya.';
            $this->recordRun($message);
            $this->error($message);

            return self::FAILURE;
        }

        try {
            $this->configureMailer($settings);
        } catch (\Throwable $e) {
            $message = 'Konfigurasi SMTP tidak dapat dibaca: '.$e->getMessage();
            $this->recordRun($message);
            $this->error($message);

            return self::FAILURE;
        }

        $sent = 0;
        $failed = 0;
        foreach ($rows as $x) {
            $email = strtolower(trim((string) $x->email_kontraktor));
            if (! filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $this->log($x, (int) today()->diffInDays($x->ekim_valid_until, false), 'failed', 'Format email transportir tidak valid.');
                $failed++;

                continue;
            }
            if (DB::table('kim_notifications')->where('nomor_polisi', $x->nomor_polisi)->where('email_to', $email)->whereDate('ekim_valid_until', $x->ekim_valid_until)->where('status', 'sent')->where('sent_at', '>=', now()->subDays(7))->exists()) {
                continue;
            }
            $remaining = (int) today()->diffInDays($x->ekim_valid_until, false);
            $status = 'sent';
            $error = null;
            try {
                Mail::raw("EKIM kendaraan {$x->nomor_polisi} ".($remaining < 0 ? 'telah kedaluwarsa' : "akan kedaluwarsa dalam $remaining hari")." pada {$x->ekim_valid_until}. Segera hubungi pengelola PRIMA untuk tindak lanjut pemeriksaan dan pembaruan EKIM.", fn ($m) => $m->to($email)->subject("Notifikasi Masa Berlaku EKIM {$x->nomor_polisi}"));
                $sent++;
            } catch (\Throwable $e) {
                $status = 'failed';
                $error = $e->getMessage();
                $failed++;
            }
            $x->email_kontraktor = $email;
            $this->log($x, $remaining, $status, $error);
        }
        $message = "Scheduler selesai: {$rows->count()} kandidat, $sent terkirim, $failed gagal.";
        $this->recordRun($message);
        $this->info($message);

        return $failed > 0 ? self::FAILURE : self::SUCCESS;
    }

    private function smtpReady($settings): bool
    {
        foreach (['smtp_host', 'smtp_port', 'smtp_from_email'] as $key) {
            if (blank($settings[$key] ?? null)) {
                return false;
            }
        }

        if (filled($settings['smtp_username'] ?? null) && blank($settings['smtp_password'] ?? null)) {
            return false;
        }

        return filter_var($settings['smtp_from_email'], FILTER_VALIDATE_EMAIL) !== false;
    }

    private function configureMailer($settings): void
    {
        $encryption = $settings['smtp_encryption'] ?? 'tls';
        $username = trim((string) ($settings['smtp_username'] ?? ''));
        $password = filled($settings['smtp_password'] ?? null) ? decrypt($settings['smtp_password']) : null;
        Config::set('mail.mailers.smtp', ['transport' => 'smtp', 'scheme' => $encryption === 'ssl' ? 'smtps' : 'smtp', 'host' => $settings['smtp_host'], 'port' => (int) $settings['smtp_port'], 'auto_tls' => $encryption !== 'none', 'username' => $username !== '' ? $username : null, 'password' => $password, 'timeout' => 30]);
        Config::set('mail.default', 'smtp');
        Config::set('mail.from', ['address' => strtolower(trim($settings['smtp_from_email'])), 'name' => $settings['smtp_from_name'] ?? 'PRIMA']);
        Mail::purge('smtp');
    }

    private function recordRun(string $status): void
    {
        DB::table('system_settings')->upsert([
            ['setting_key' => 'cron_last_run', 'setting_value' => now()->toDateTimeString(), 'updated_at' => now()],
            ['setting_key' => 'cron_last_status', 'setting_value' => $status, 'updated_at' => now()],
        ], ['setting_key'], ['setting_value', 'updated_at']);
    }

    private function log(object $x, int $remaining, string $status, ?string $error): void
    {
        DB::table('kim_notifications')->insert(['nomor_polisi' => $x->nomor_polisi, 'nama_transport' => $x->nama_transport, 'email_to' => $x->email_kontraktor, 'ekim_valid_until' => $x->ekim_valid_until, 'hari_tersisa' => $remaining, 'status' => $status, 'error_message' => $error, 'sent_at' => now()]);
    }
}
