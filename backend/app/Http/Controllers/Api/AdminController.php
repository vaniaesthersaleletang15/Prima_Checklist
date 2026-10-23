<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\RetentionService;
use App\Support\SimpleXlsx;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Process\Process;

class AdminController extends Controller
{
    private const DOCUMENT_CHECKLIST_ITEMS = [
        'STNK' => 'STNK',
        'PAJAK' => 'PAJAK',
        'SIM' => 'SIMFIT (Industri)',
        'SURAT_KEUR' => 'Surat Keur DLLAAJR',
        'SURAT_TERA' => 'Surat Tera Metrologi',
    ];

    private function ok(string $message = 'OK', mixed $data = null, int $status = 200): JsonResponse
    {
        return response()->json(['success' => true, 'message' => $message, 'data' => $data], $status);
    }

    private function fail(string $message, int $status = 422, mixed $data = null): JsonResponse
    {
        return response()->json(['success' => false, 'message' => $message, 'data' => $data], $status);
    }

    private function admin(Request $r): void
    {
        if ($r->user()->role !== 'admin') {
            throw new HttpException(403, 'Akses ditolak.');
        }
    }

    private function setting(string $key, mixed $default = null): mixed
    {
        return DB::table('system_settings')->where('setting_key', $key)->value('setting_value') ?? $default;
    }

    private function setSetting(string $key, mixed $value): void
    {
        DB::table('system_settings')->upsert([['setting_key' => $key, 'setting_value' => (string) $value, 'updated_at' => now()]], ['setting_key'], ['setting_value', 'updated_at']);
    }

    private function audit(Request $r, string $action, string $description, ?int $form = null): void
    {
        DB::table('audit_log')->insert(['formulir_id' => $form, 'action' => $action, 'user_name' => $r->user()->username, 'ip_address' => $r->ip(), 'description' => $description, 'created_at' => now()]);
    }

    public function users(Request $r): JsonResponse
    {
        $this->admin($r);

        $users = User::select('id', 'username', 'full_name', 'email', 'phone', 'department', 'position', 'role', 'status', 'last_login', 'created_at')
            ->latest()
            ->get()
            ->map(fn (User $user) => [
                'id' => $user->id,
                'full_name' => $user->full_name,
                'email' => $user->email,
                'phone' => $user->phone,
                'department' => $user->department,
                'position' => $user->position,
                'role' => $user->role,
                'status' => $user->status,
                'last_login' => $user->last_login,
                'created_at' => $user->created_at,
                'is_primary_admin' => $user->username === 'admin',
            ]);

        return $this->ok('OK', $users);
    }

    public function createUser(Request $r): JsonResponse
    {
        $this->admin($r);
        $r->merge(['email' => strtolower(trim((string) $r->email))]);
        $v = Validator::make($r->all(), [
            'full_name' => ['required', 'string', 'max:100'],
            'email' => ['required', 'email', 'max:100', Rule::unique('users', 'email')],
            'phone' => ['nullable', 'string', 'max:20'],
            'department' => ['nullable', 'string', 'max:100'],
            'position' => ['nullable', 'string', 'max:100'],
            'role' => ['required', Rule::in(['hsse', 'pengurus'])],
            'password' => ['required', 'string', 'max:100', Password::min(8)->mixedCase()->numbers()->symbols()],
        ], [
            'email.unique' => 'Email sudah digunakan oleh akun lain.',
            'password.min' => 'Password minimal 8 karakter.',
            'password.mixed' => 'Password harus mengandung huruf besar dan huruf kecil.',
            'password.numbers' => 'Password harus mengandung minimal satu angka.',
            'password.symbols' => 'Password harus mengandung minimal satu simbol.',
        ]);
        if ($v->fails()) {
            return $this->fail($v->errors()->first(), 422, $v->errors());
        }
        if (DB::table('user_registrations')->whereRaw('LOWER(email) = ?', [$r->email])->where('status', 'pending')->exists()) {
            return $this->fail('Email memiliki pendaftaran yang masih menunggu review. Tinjau melalui menu Review Pendaftaran.', 409);
        }

        $user = User::create([
            'username' => 'user_'.substr(hash('sha256', $r->email), 0, 32),
            'full_name' => $r->full_name,
            'email' => $r->email,
            'phone' => $r->phone,
            'department' => $r->department,
            'position' => $r->position,
            'role' => $r->role,
            'status' => 'active',
            'password' => $r->password,
        ]);
        $this->audit($r, 'USER_CREATE', "Akun {$user->email} dibuat dengan role {$user->role}");

        return $this->ok('Akun berhasil dibuat dan langsung aktif.', [
            'id' => $user->id,
            'full_name' => $user->full_name,
            'email' => $user->email,
            'role' => $user->role,
        ], 201);
    }

    public function updateUser(Request $r, int $id): JsonResponse
    {
        $this->admin($r);
        $r->merge(['email' => strtolower(trim((string) $r->email))]);
        $v = Validator::make($r->all(), ['full_name' => 'required|max:100', 'email' => ['required', 'email', 'max:100', Rule::unique('users', 'email')->ignore($id)], 'phone' => 'nullable|max:20', 'department' => 'nullable|max:100', 'position' => 'nullable|max:100', 'role' => ['required', Rule::in(['admin', 'user', 'pengurus', 'hsse', 'manager_hsse'])]]);
        if ($v->fails()) {
            return $this->fail($v->errors()->first(), 422, $v->errors());
        }$u = User::find($id);
        if (! $u) {
            return $this->fail('User tidak ditemukan.', 404);
        }if ($u->username === 'admin' && $r->role !== 'admin') {
            return $this->fail('Role akun admin utama tidak dapat diubah.', 409);
        }$u->fill($r->only('full_name', 'email', 'phone', 'department', 'position', 'role'))->fill(['email' => strtolower(trim((string) $r->email))])->save();
        $this->audit($r, 'USER_UPDATE', "Akun {$u->username} diperbarui");

        return $this->ok('Data pengguna berhasil diperbarui.');
    }

    public function toggleUser(Request $r, int $id): JsonResponse
    {
        $this->admin($r);
        $u = User::find($id);
        if (! $u) {
            return $this->fail('User tidak ditemukan.', 404);
        }if ($u->id === $r->user()->id) {
            return $this->fail('Tidak dapat menonaktifkan akun sendiri.', 409);
        }$u->status = $r->input('status') === 'active' ? 'active' : 'inactive';
        $u->save();
        if ($u->status === 'inactive') {
            $u->tokens()->delete();
        }$this->audit($r, 'USER_STATUS', "Status {$u->username}: {$u->status}");

        return $this->ok('Status pengguna berhasil diperbarui.');
    }

    public function deleteUser(Request $r, int $id): JsonResponse
    {
        $this->admin($r);
        $user = User::find($id);

        if (! $user) {
            return $this->fail('User tidak ditemukan.', 404);
        }
        if ($user->id === $r->user()->id) {
            return $this->fail('Akun yang sedang digunakan tidak dapat dihapus.', 409);
        }
        if ($user->username === 'admin') {
            return $this->fail('Akun admin utama tidak dapat dihapus.', 409);
        }
        if ($user->role === 'admin' && User::where('role', 'admin')->count() <= 1) {
            return $this->fail('Administrator terakhir tidak dapat dihapus.', 409);
        }

        $username = $user->username;
        DB::transaction(function () use ($user): void {
            $user->tokens()->delete();
            DB::table('sessions')->where('user_id', $user->id)->delete();
            $user->delete();
        });
        $this->audit($r, 'USER_DELETE', "Akun {$username} dihapus permanen");

        return $this->ok('Pengguna berhasil dihapus.');
    }

    public function resetPassword(Request $r, int $id): JsonResponse
    {
        $this->admin($r);
        $v = Validator::make($r->all(), [
            'new_password' => ['required', 'string', 'max:100', Password::min(8)->mixedCase()->numbers()->symbols()],
        ], [
            'new_password.min' => 'Password minimal 8 karakter.',
            'new_password.mixed' => 'Password harus mengandung huruf besar dan huruf kecil.',
            'new_password.numbers' => 'Password harus mengandung minimal satu angka.',
            'new_password.symbols' => 'Password harus mengandung minimal satu simbol.',
        ]);
        if ($v->fails()) {
            return $this->fail($v->errors()->first());
        }$u = User::find($id);
        if (! $u) {
            return $this->fail('User tidak ditemukan.', 404);
        }$u->password = Hash::make($r->new_password);
        $u->save();
        $u->tokens()->delete();
        $this->audit($r, 'PASSWORD_RESET', "Password {$u->username} direset");

        return $this->ok('Password berhasil direset.');
    }

    public function registrations(Request $r): JsonResponse
    {
        $this->admin($r);

        return $this->ok('OK', DB::table('user_registrations')->select('id', 'email', 'full_name', 'phone', 'reason', 'requested_role', 'status', 'reviewed_by', 'reviewed_at', 'rejection_reason', 'created_at', 'updated_at')->latest()->get());
    }

    public function reviewRegistration(Request $r, int $id): JsonResponse
    {
        $this->admin($r);
        $reg = DB::table('user_registrations')->where('id', $id)->first();
        if (! $reg) {
            return $this->fail('Pendaftaran tidak ditemukan.', 404);
        }if ($reg->status !== 'pending') {
            return $this->fail('Pendaftaran sudah ditinjau.', 409);
        }if ($r->input('action') === 'approve') {
            DB::transaction(function () use ($reg, $r) {
                User::create(['username' => $reg->username, 'password' => $reg->password, 'full_name' => $reg->full_name, 'email' => $reg->email, 'phone' => $reg->phone, 'role' => $reg->requested_role ?: 'user', 'status' => 'active']);
                DB::table('user_registrations')->where('id', $reg->id)->update(['status' => 'approved', 'reviewed_by' => $r->user()->id, 'reviewed_at' => now(), 'updated_at' => now()]);
            });
            $message = 'Pendaftaran berhasil disetujui.';
        } elseif ($r->input('action') === 'reject') {
            DB::table('user_registrations')->where('id', $id)->update(['status' => 'rejected', 'rejection_reason' => $r->input('reason'), 'reviewed_by' => $r->user()->id, 'reviewed_at' => now(), 'updated_at' => now()]);
            $message = 'Pendaftaran ditolak.';
        } else {
            return $this->fail('Aksi tidak valid.');
        }$this->audit($r, 'REGISTRATION_REVIEW', "Pendaftaran {$reg->email}: {$r->input('action')}");

        return $this->ok($message);
    }

    public function documents(Request $r): JsonResponse
    {
        $q = DB::table('dokumen_kendaraan as d')->leftJoin('users as u', 'u.id', '=', 'd.uploaded_by')->select('d.*', 'u.full_name as uploader_name');
        if ($r->user()->role === 'pengurus') {
            $q->where('d.uploaded_by', $r->user()->id);
        } elseif ($r->user()->role !== 'admin') {
            return $this->fail('Akses ditolak.', 403);
        }

        return $this->ok('OK', $q->latest('d.created_at')->limit(250)->get());
    }

    public function uploadDocument(Request $r): JsonResponse
    {
        if ($r->user()->role !== 'pengurus') {
            return $this->fail('Hanya pengurus yang dapat mengunggah dokumen.', 403);
        }$v = Validator::make($r->all(), ['file' => 'required|file|max:5120|mimes:pdf,jpg,jpeg,png|mimetypes:application/pdf,image/jpeg,image/png', 'jenis_dokumen' => ['required', Rule::in(['STNK', 'PAJAK', 'SIM', 'SURAT_KEUR', 'SURAT_TERA', 'KIM', 'LAINNYA'])], 'nomor_polisi' => 'required|max:20', 'tanggal_berlaku' => 'nullable|date|after_or_equal:today']);
        if ($v->fails()) {
            return $this->fail($v->errors()->first(), 422, $v->errors());
        }$plate = strtoupper(trim($r->nomor_polisi));
        if (! DB::table('pengurus_kendaraan')->where(['user_id' => $r->user()->id, 'nomor_polisi' => $plate])->exists()) {
            return $this->fail('Kendaraan bukan tanggung jawab Anda.', 403);
        }if (in_array($r->jenis_dokumen, ['STNK', 'PAJAK', 'SIM', 'SURAT_KEUR', 'SURAT_TERA'], true) && ! $r->tanggal_berlaku) {
            return $this->fail('Tanggal berlaku dokumen wajib diisi.');
        }$path = $r->file('file')->store('dokumen', 'private');
        DB::table('dokumen_kendaraan')->insert(['nomor_polisi' => $plate, 'nama_transport' => $r->nama_transport, 'jenis_dokumen' => $r->jenis_dokumen, 'nama_file_asli' => $r->file('file')->getClientOriginalName(), 'file_path' => $path, 'tanggal_berlaku' => $r->tanggal_berlaku, 'keterangan' => $r->keterangan, 'uploaded_by' => $r->user()->id, 'status' => 'PENDING', 'created_at' => now(), 'updated_at' => now()]);

        return $this->ok('Dokumen berhasil diunggah dan menunggu verifikasi.');
    }

    public function deleteDocument(Request $r, int $id): JsonResponse
    {
        if ($r->user()->role !== 'pengurus') {
            return $this->fail('Akses ditolak.', 403);
        }$d = DB::table('dokumen_kendaraan')->where(['id' => $id, 'uploaded_by' => $r->user()->id, 'status' => 'PENDING'])->first();
        if (! $d) {
            return $this->fail('Dokumen tidak ditemukan atau tidak dapat dihapus.', 404);
        }Storage::disk('private')->delete($d->file_path);
        DB::table('dokumen_kendaraan')->where('id', $id)->delete();

        return $this->ok('Dokumen berhasil dihapus.');
    }

    public function reviewDocument(Request $r, int $id): JsonResponse
    {
        $this->admin($r);
        $d = DB::table('dokumen_kendaraan')->where('id', $id)->first();
        if (! $d) {
            return $this->fail('Dokumen tidak ditemukan.', 404);
        }$status = $r->input('action') === 'approve' ? 'DISETUJUI' : ($r->input('action') === 'reject' ? 'DITOLAK' : null);
        if (! $status) {
            return $this->fail('Aksi tidak valid.');
        }
        $updatedDraftItems = DB::transaction(function () use ($d, $id, $r, $status): int {
            DB::table('dokumen_kendaraan')->where('id', $id)->update(['status' => $status, 'catatan_admin' => $r->input('catatan_admin', $r->input('reason')), 'reviewed_by' => $r->user()->id, 'reviewed_at' => now(), 'updated_at' => now()]);

            if ($status !== 'DISETUJUI' || empty($d->tanggal_berlaku) || ! isset(self::DOCUMENT_CHECKLIST_ITEMS[$d->jenis_dokumen])) {
                return 0;
            }

            $activeExpiry = DB::table('dokumen_kendaraan')
                ->where('nomor_polisi', $d->nomor_polisi)
                ->where('jenis_dokumen', $d->jenis_dokumen)
                ->where('status', 'DISETUJUI')
                ->whereNotNull('tanggal_berlaku')
                ->orderByDesc('tanggal_berlaku')
                ->orderByDesc('reviewed_at')
                ->value('tanggal_berlaku');

            $draftIds = DB::table('formulir_checklist')
                ->where('nomor_polisi', $d->nomor_polisi)
                ->where('status_approval', 'draft')
                ->pluck('id');

            if ($draftIds->isEmpty()) {
                return 0;
            }

            return DB::table('checklist_items')
                ->whereIn('formulir_id', $draftIds)
                ->where('item_name', self::DOCUMENT_CHECKLIST_ITEMS[$d->jenis_dokumen])
                ->update(['tanggal_expire' => $activeExpiry]);
        });
        $this->audit($r, 'DOCUMENT_REVIEW', "Dokumen {$d->jenis_dokumen} {$d->nomor_polisi} menjadi $status; $updatedDraftItems item checklist draft diperbarui");

        $message = $status === 'DISETUJUI' && isset(self::DOCUMENT_CHECKLIST_ITEMS[$d->jenis_dokumen])
            ? 'Dokumen disetujui. Masa berlaku surat kendaraan dan checklist draft telah diperbarui otomatis.'
            : 'Status dokumen berhasil diperbarui.';

        return $this->ok($message, ['updated_draft_items' => $updatedDraftItems]);
    }

    public function downloadDocument(Request $r, int $id)
    {
        $d = DB::table('dokumen_kendaraan')->where('id', $id)->first();
        if (! $d) {
            abort(404);
        }if ($r->user()->role !== 'admin' && $d->uploaded_by !== $r->user()->id) {
            abort(403);
        }if (! Storage::disk('private')->exists($d->file_path)) {
            abort(404);
        }

        return Storage::disk('private')->download($d->file_path, $d->nama_file_asli);
    }

    public function audits(Request $r): JsonResponse
    {
        $this->admin($r);
        $s = trim($r->query('search', ''));
        $q = DB::table('audit_log as a')->leftJoin('formulir_checklist as f', 'f.id', '=', 'a.formulir_id')->select('a.*', 'f.nomor_polisi');
        if ($s) {
            $q->where(fn ($x) => $x->where('a.user_name', 'ilike', "%$s%")->orWhere('a.action', 'ilike', "%$s%")->orWhere('a.description', 'ilike', "%$s%"));
        }

        return $this->ok('OK', $q->latest('a.created_at')->limit(250)->get());
    }

    public function alerts(Request $r): JsonResponse
    {
        $this->admin($r);
        $limit = today()->addDays(30)->toDateString();
        $rows = DB::table('formulir_checklist as f')->leftJoin('kendaraan as k', 'k.nomor_polisi', '=', 'f.nomor_polisi')->where('f.status_approval', 'approved')->whereNotNull('f.ekim_valid_until')->where('f.ekim_valid_until', '<=', $limit)->whereRaw('f.id=(SELECT MAX(f2.id) FROM formulir_checklist f2 WHERE f2.nomor_polisi=f.nomor_polisi AND f2.status_approval=?)', ['approved'])->select('f.id', 'f.nomor_polisi', 'f.merk_mobil', 'f.nama_transport', 'k.email_kontraktor', 'f.jenis_kendaraan as jenis', 'f.ekim_valid_until')->get()->map(function ($x) {
            $x->effective_valid_until = $x->ekim_valid_until;
            $x->hari_tersisa = today()->diffInDays($x->ekim_valid_until, false);
            $x->status_alert = $x->hari_tersisa < 0 ? 'SUDAH_EXPIRED' : 'PERLU_INSPEKSI';

            return $x;
        });

        return $this->ok('OK', $rows);
    }

    public function settings(Request $r): JsonResponse
    {
        $this->admin($r);
        $tables = collect(DB::select('SELECT relname AS name, n_live_tup AS row_count, pg_total_relation_size(relid) AS size_bytes FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC'))->map(fn ($x) => ['name' => $x->name, 'row_count' => (int) $x->row_count, 'size_mb' => round($x->size_bytes / 1048576, 2)]);
        $backups = collect(Storage::disk('local')->files('backups'))->filter(fn ($x) => str_ends_with($x, '.dump') || str_ends_with($x, '.json.gz'))->map(fn ($x) => ['filename' => basename($x), 'size' => $this->bytes(Storage::disk('local')->size($x)), 'created_at' => date('Y-m-d H:i:s', Storage::disk('local')->lastModified($x)), 'checksum' => Storage::disk('local')->exists($x.'.sha256') ? trim(Storage::disk('local')->get($x.'.sha256')) : null, 'status' => 'verified'])->sortByDesc('created_at')->values()->take(10);
        $last = $this->setting('cron_last_run');

        $free = disk_free_space(storage_path());
        $total = disk_total_space(storage_path());
        $smtpUsername = $this->setting('smtp_username');
        $smtpReady = filled($this->setting('smtp_host'))
            && filled($this->setting('smtp_port'))
            && filled($this->setting('smtp_from_email'))
            && (blank($smtpUsername) || filled($this->setting('smtp_password')));

        return $this->ok('OK', ['php_version' => PHP_VERSION, 'database' => config('database.connections.pgsql.database'), 'timezone' => config('app.timezone'), 'upload_max' => ini_get('upload_max_filesize'), 'memory_limit' => ini_get('memory_limit'), 'app_version' => config('app.version'), 'tables' => $tables, 'health' => ['database' => ['ok' => true, 'label' => 'Terhubung PostgreSQL'], 'uploads' => ['ok' => true, 'label' => 'Private storage aktif'], 'backup_storage' => ['ok' => is_writable(storage_path('app/private')), 'label' => 'Siap digunakan'], 'smtp' => ['ok' => $smtpReady, 'label' => $smtpReady ? 'Terkonfigurasi' : 'Belum lengkap'], 'scheduler' => ['ok' => $last && strtotime($last) >= strtotime('-36 hours'), 'label' => $last ? 'Aktif' : 'Belum pernah berjalan']], 'storage' => ['free_bytes' => $free, 'total_bytes' => $total, 'free_label' => $this->bytes($free), 'total_label' => $this->bytes($total), 'upload_path' => 'private/dokumen', 'backup_path' => 'private/backups'], 'scheduler' => ['last_run' => $last, 'healthy' => $last && strtotime($last) >= strtotime('-36 hours')], 'backup' => ['last_at' => $this->setting('last_backup_at'), 'last_status' => $this->setting('last_backup_status', 'never'), 'items' => $backups], 'policies' => ['maintenance_mode' => $this->setting('maintenance_mode', '0') === '1', 'maintenance_message' => $this->setting('maintenance_message', 'Sistem sedang dalam pemeliharaan. Silakan coba kembali nanti.'), 'session_timeout_minutes' => (int) $this->setting('session_timeout_minutes', 60), 'audit_retention_days' => (int) $this->setting('audit_retention_days', 365), 'backup_retention_days' => (int) $this->setting('backup_retention_days', 30)]]);
    }

    private function bytes(float|int|false $n): string
    {
        if ($n === false) {
            return 'Tidak tersedia';
        }$u = ['B', 'KB', 'MB', 'GB', 'TB'];
        $p = $n ? min((int) floor(log($n, 1024)), 4) : 0;

        return number_format($n / (1024 ** $p), $p > 1 ? 2 : 0, ',', '.').' '.$u[$p];
    }

    public function saveSettings(Request $r): JsonResponse
    {
        $this->admin($r);
        $values = ['session_timeout_minutes' => max(15, min(480, $r->integer('session_timeout_minutes', 60))), 'audit_retention_days' => max(90, min(3650, $r->integer('audit_retention_days', 365))), 'backup_retention_days' => max(7, min(365, $r->integer('backup_retention_days', 30))), 'maintenance_mode' => $r->boolean('maintenance_mode') ? '1' : '0', 'maintenance_message' => mb_substr(trim($r->input('maintenance_message')) ?: 'Sistem sedang dalam pemeliharaan.', 0, 250)];
        foreach ($values as $k => $v) {
            $this->setSetting($k, $v);
        }$this->audit($r, 'SYSTEM_SETTINGS', 'Pengaturan sistem diperbarui');

        return $this->ok('Pengaturan sistem berhasil disimpan.');
    }

    public function retention(Request $r, RetentionService $retention): JsonResponse
    {
        $this->admin($r);
        $result = $retention->apply();
        $this->audit($r, 'RETENTION', "{$result['audit_deleted']} audit dan {$result['backups_deleted']} backup lama dihapus");

        return $this->ok("Retensi diterapkan. {$result['audit_deleted']} audit dan {$result['backups_deleted']} backup lama dihapus.", $result);
    }

    public function backup(Request $r): JsonResponse
    {
        $this->admin($r);
        $dir = storage_path('app/private/backups');
        if (! is_dir($dir)) {
            mkdir($dir, 0750, true);
        }$file = 'prima-db-'.now()->format('Ymd-His').'-'.bin2hex(random_bytes(3)).'.dump';
        $path = $dir.DIRECTORY_SEPARATOR.$file;
        $cfg = config('database.connections.pgsql');
        $process = new Process([
            config('prima.pg_dump_binary', 'pg_dump'),
            '--format=custom',
            '--no-owner',
            '--no-privileges',
            '--exclude-table-data=public.personal_access_tokens',
            '--exclude-table-data=public.sessions',
            '--exclude-table-data=public.cache',
            '--exclude-table-data=public.cache_locks',
            '--exclude-table-data=public.jobs',
            '--exclude-table-data=public.failed_jobs',
            '--exclude-table-data=public.job_batches',
            '--exclude-table-data=public.password_reset_tokens',
            '--file='.$path,
            '--host='.$cfg['host'],
            '--port='.(string) $cfg['port'],
            '--username='.$cfg['username'],
            $cfg['database'],
        ], null, ['PGPASSWORD' => $cfg['password']]);
        $process->setTimeout(300);
        $process->run();
        if (! $process->isSuccessful()) {
            logger()->warning('pg_dump gagal; menggunakan backup portabel Laravel', [
                'error' => $process->getErrorOutput(),
                'output' => $process->getOutput(),
                'exit_code' => $process->getExitCode(),
            ]);
            @unlink($path);
            $file = str_replace('.dump', '.json.gz', $file);
            $path = $dir.DIRECTORY_SEPARATOR.$file;
            $this->createPortableBackup($path);
        }
        $checksum = hash_file('sha256', $path);
        file_put_contents($path.'.sha256', $checksum);
        app(RetentionService::class)->pruneBackups();
        $this->setSetting('last_backup_at', now()->toDateTimeString());
        $this->setSetting('last_backup_status', 'success');
        $this->audit($r, 'BACKUP', "Backup $file dibuat");

        return $this->ok('Backup database berhasil dibuat.', ['filename' => $file, 'size' => $this->bytes(filesize($path)), 'checksum' => $checksum, 'format' => str_ends_with($file, '.dump') ? 'postgresql-custom' : 'prima-portable-json']);
    }

    private function createPortableBackup(string $path): void
    {
        $tables = collect(DB::select("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"))->pluck('tablename');
        $payload = [
            'format' => 'prima-portable-backup-v1',
            'created_at' => now()->toIso8601String(),
            'database' => config('database.connections.pgsql.database'),
            'tables' => [],
        ];
        $ephemeral = ['personal_access_tokens', 'sessions', 'cache', 'cache_locks', 'jobs', 'failed_jobs', 'job_batches', 'password_reset_tokens'];
        foreach ($tables as $table) {
            $payload['tables'][$table] = in_array($table, $ephemeral, true) ? [] : DB::table($table)->orderBy(Schema::hasColumn($table, 'id') ? 'id' : Schema::getColumnListing($table)[0])->get()->map(fn ($row) => (array) $row)->all();
        }
        $compressed = gzencode(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), 9);
        if ($compressed === false || file_put_contents($path, $compressed, LOCK_EX) === false) {
            throw new \RuntimeException('Gagal membuat backup portabel.');
        }
    }

    public function notifications(Request $r): JsonResponse
    {
        $this->admin($r);
        $keys = ['smtp_host', 'smtp_port', 'smtp_encryption', 'smtp_username', 'smtp_from_email', 'smtp_from_name', 'notif_days_threshold'];
        $cfg = [];
        foreach ($keys as $k) {
            $cfg[$k] = $this->setting($k, ['smtp_host' => 'smtp.gmail.com', 'smtp_port' => '587', 'smtp_encryption' => 'tls', 'notif_days_threshold' => '30'][$k] ?? '');
        }

        $credentialsReady = blank($cfg['smtp_username'] ?? null) || filled($this->setting('smtp_password'));
        $smtpReady = collect(['smtp_host', 'smtp_port', 'smtp_from_email'])->every(fn ($key) => filled($cfg[$key] ?? null)) && $credentialsReady;

        return $this->ok('OK', ['config' => $cfg, 'smtp_ready' => $smtpReady, 'history' => DB::table('kim_notifications as n')->leftJoin('users as u', 'u.id', '=', 'n.sent_by')->select('n.*', 'u.full_name as sender_name')->latest('n.sent_at')->limit(100)->get(), 'cron_url' => url('/api/v1/scheduler/run/'.$this->cronSecret()), 'cron_last_run' => $this->setting('cron_last_run'), 'cron_last_status' => $this->setting('cron_last_status')]);
    }

    public function saveNotifications(Request $r): JsonResponse
    {
        $this->admin($r);
        $validated = $r->validate([
            'smtp_host' => ['required', 'string', 'max:255'],
            'smtp_port' => ['required', 'integer', 'between:1,65535'],
            'smtp_encryption' => ['required', Rule::in(['tls', 'ssl', 'none'])],
            'smtp_username' => ['nullable', 'string', 'max:255'],
            'smtp_from_email' => ['required', 'email', 'max:255'],
            'smtp_from_name' => ['nullable', 'string', 'max:255'],
            'smtp_password' => ['nullable', 'string', 'max:1000'],
            'notif_days_threshold' => ['required', 'integer', 'between:0,365'],
        ]);
        $username = trim((string) ($validated['smtp_username'] ?? ''));
        if ($username !== '' && blank($validated['smtp_password'] ?? null) && blank($this->setting('smtp_password'))) {
            return $this->fail('Password SMTP wajib diisi jika akun SMTP digunakan.');
        }
        foreach (['smtp_host', 'smtp_port', 'smtp_encryption', 'smtp_username', 'smtp_from_email', 'smtp_from_name', 'notif_days_threshold'] as $k) {
            $this->setSetting($k, $validated[$k] ?? '');
        }if (filled($validated['smtp_password'] ?? null)) {
            $this->setSetting('smtp_password', encrypt($validated['smtp_password']));
        } elseif ($username === '') {
            DB::table('system_settings')->where('setting_key', 'smtp_password')->delete();
        }

        return $this->ok('Konfigurasi notifikasi berhasil disimpan.');
    }

    private function cronSecret(): string
    {
        $x = $this->setting('cron_secret');
        if (! $x) {
            $x = bin2hex(random_bytes(24));
            $this->setSetting('cron_secret', $x);
        }

        return $x;
    }

    public function regenerateCron(Request $r): JsonResponse
    {
        $this->admin($r);
        $this->setSetting('cron_secret', bin2hex(random_bytes(24)));

        return $this->ok('Kunci cron berhasil dibuat ulang.');
    }

    public function runScheduler(Request $r, string $secret): JsonResponse
    {
        $stored = (string) $this->setting('cron_secret', '');
        if ($stored === '' || ! hash_equals($stored, $secret)) {
            return $this->fail('Kunci scheduler tidak valid.', 403);
        }$exitCode = Artisan::call('prima:notifications');

        if ($exitCode !== 0) {
            return $this->fail(trim(Artisan::output()) ?: 'Scheduler notifikasi gagal dijalankan.', 503);
        }

        return $this->ok('Scheduler notifikasi selesai dijalankan.');
    }

    public function myVehicles(Request $r): JsonResponse
    {
        if ($r->user()->role !== 'pengurus') {
            return $this->fail('Akses ditolak.', 403);
        }
        $uid = $r->user()->id;
        $rows = DB::table('pengurus_kendaraan as p')->leftJoin('dokumen_kendaraan as d', fn ($j) => $j->on('d.nomor_polisi', '=', 'p.nomor_polisi')->where('d.uploaded_by', $uid))->where('p.user_id', $uid)->groupBy('p.nomor_polisi', 'p.nama_transport')->select('p.nomor_polisi', 'p.nama_transport')->selectRaw("SUM(CASE WHEN d.status='PENDING' THEN 1 ELSE 0 END) pending_dokumen")->selectRaw("SUM(CASE WHEN d.status='DISETUJUI' THEN 1 ELSE 0 END) disetujui_dokumen")->selectRaw("SUM(CASE WHEN d.status='DITOLAK' THEN 1 ELSE 0 END) ditolak_dokumen")->get();

        return $this->ok('OK', $rows);
    }

    public function registerMyVehicle(Request $r): JsonResponse
    {
        if ($r->user()->role !== 'pengurus') {
            return $this->fail('Akses ditolak.', 403);
        }$plate = strtoupper(trim($r->input('nomor_polisi')));
        if (! $plate) {
            return $this->fail('Nomor polisi wajib diisi.');
        }$exists = DB::table('pengurus_kendaraan')->where(['user_id' => $r->user()->id, 'nomor_polisi' => $plate])->exists();
        if (! $exists) {
            DB::table('pengurus_kendaraan')->insert(['user_id' => $r->user()->id, 'nomor_polisi' => $plate, 'nama_transport' => $r->input('nama_transport'), 'created_at' => now(), 'updated_at' => now()]);
        }

        return $this->ok($exists ? 'Kendaraan sudah terdaftar.' : 'Kendaraan berhasil didaftarkan.');
    }

    public function userVehicles(Request $r): JsonResponse
    {
        if ($r->user()->role !== 'user') {
            return $this->fail('Akses ditolak.', 403);
        }

        $rows = DB::table('kendaraan as k')
            ->leftJoin('pengurus_kendaraan as pk', 'pk.nomor_polisi', '=', 'k.nomor_polisi')
            ->leftJoin('users as u', 'u.id', '=', 'pk.user_id')
            ->where('k.created_by', $r->user()->id)
            ->select('k.*', 'u.id as user_id_transportir', 'u.full_name as akun_transportir', 'u.email as email_akun_transportir')
            ->latest('k.created_at')
            ->get();

        return $this->ok('OK', $rows);
    }

    public function registerUserVehicle(Request $r): JsonResponse
    {
        if ($r->user()->role !== 'user') {
            return $this->fail('Akses ditolak.', 403);
        }
        $r->merge(['nomor_polisi' => strtoupper(trim((string) $r->nomor_polisi)), 'email_kontraktor' => strtolower(trim((string) $r->email_kontraktor))]);
        $v = Validator::make(
            $r->all(),
            ['jenis' => ['required', Rule::in(['SPBU', 'INDUSTRI'])], 'nomor_polisi' => ['required', 'regex:/^[A-Z0-9 .-]{3,20}$/', 'unique:kendaraan,nomor_polisi'], 'merk_mobil' => 'required|max:100', 'tahun_kendaraan' => 'nullable|integer|min:1980|max:'.(date('Y') + 1), 'nama_transport' => 'required|max:100', 'email_kontraktor' => 'required|email|max:100', 'user_id_transportir' => ['required', 'integer', Rule::exists('users', 'id')->where(fn ($q) => $q->where('role', 'pengurus')->where('status', 'active'))]],
            [
                'nomor_polisi.unique' => 'Nomor polisi :input sudah terdaftar. Gunakan nomor polisi lain atau minta SPV HSSE menetapkan kendaraan yang sudah ada ke akun transportir.',
                'nomor_polisi.regex' => 'Format nomor polisi tidak valid.',
                'user_id_transportir.required' => 'Akun transportir/pengurus wajib dipilih.',
                'user_id_transportir.exists' => 'Akun transportir/pengurus tidak ditemukan atau tidak aktif.',
                'email_kontraktor.email' => 'Format email kontraktor/PJ tidak valid.',
            ]
        );
        if ($v->fails()) {
            return $this->fail($v->errors()->first(), 422, $v->errors());
        }
        $id = DB::transaction(function () use ($r) {
            $id = DB::table('kendaraan')->insertGetId($r->only('jenis', 'nomor_polisi', 'merk_mobil', 'tahun_kendaraan', 'produk_kapasitas', 'nama_transport', 'email_kontraktor') + ['status' => 'AKTIF', 'created_by' => $r->user()->id, 'created_at' => now(), 'updated_at' => now()]);
            DB::table('pengurus_kendaraan')->insert(['user_id' => $r->integer('user_id_transportir'), 'nomor_polisi' => $r->nomor_polisi, 'nama_transport' => $r->nama_transport, 'created_at' => now(), 'updated_at' => now()]);

            return $id;
        });
        $transportir = User::find($r->integer('user_id_transportir'));
        $this->audit($r, 'CREATE', "Registrasi kendaraan {$r->nomor_polisi} untuk akun transportir {$transportir?->email}");

        return $this->ok('Kendaraan berhasil diregistrasikan dan ditautkan ke akun transportir.', ['id' => $id, 'transportir' => $transportir?->only(['id', 'full_name', 'email'])]);
    }

    public function saveVehicle(Request $r): JsonResponse
    {
        $this->admin($r);
        if ($r->input('action') === 'delete') {
            DB::table('kendaraan')->where('id', $r->integer('id'))->delete();

            return $this->ok('Kendaraan berhasil dihapus.');
        }
        $r->merge(['nomor_polisi' => strtoupper(trim((string) $r->nomor_polisi)), 'email_kontraktor' => strtolower(trim((string) $r->email_kontraktor))]);
        $v = Validator::make($r->all(), ['jenis' => ['required', Rule::in(['SPBU', 'INDUSTRI'])], 'nomor_polisi' => 'required|max:20', 'merk_mobil' => 'required|max:100', 'email_kontraktor' => 'required|email|max:100', 'user_id_transportir' => ['required', 'integer', Rule::exists('users', 'id')->where(fn ($q) => $q->where('role', 'pengurus')->where('status', 'active'))]]);
        if ($v->fails()) {
            return $this->fail($v->errors()->first());
        }$data = $r->only('jenis', 'nomor_polisi', 'merk_mobil', 'tahun_kendaraan', 'produk_kapasitas', 'nama_transport', 'email_kontraktor', 'status');
        $data['nomor_polisi'] = strtoupper($data['nomor_polisi']);
        $data['updated_at'] = now();
        if ($r->integer('id')) {
            DB::table('kendaraan')->where('id', $r->integer('id'))->update($data);
            $id = $r->integer('id');
        } else {
            $data += ['created_by' => $r->user()->id, 'created_at' => now()];
            $id = DB::table('kendaraan')->insertGetId($data);
        }
        $uid = $r->integer('user_id_transportir');
        DB::table('pengurus_kendaraan')->where('nomor_polisi', $data['nomor_polisi'])->delete();
        DB::table('pengurus_kendaraan')->insert(['user_id' => $uid, 'nomor_polisi' => $data['nomor_polisi'], 'nama_transport' => $data['nama_transport'] ?? null, 'created_at' => now(), 'updated_at' => now()]);

        return $this->ok('Data kendaraan berhasil disimpan.', ['id' => $id]);
    }

    public function export(Request $r): BinaryFileResponse
    {
        if (! in_array($r->user()->role, ['admin', 'user', 'hsse', 'manager_hsse'], true)) {
            throw new HttpException(403, 'Akses ditolak.');
        }
        $query = DB::table('formulir_checklist');
        if ($search = trim($r->query('search', ''))) {
            $query->where(fn ($x) => $x->where('nomor_polisi', 'ilike', "%$search%")->orWhere('nama_transport', 'ilike', "%$search%")->orWhere('nomor_urut', 'ilike', "%$search%"));
        }
        if ($date = $r->query('dateFrom')) {
            $query->whereDate('tanggal_pemeriksaan', '>=', $date);
        }
        if ($date = $r->query('dateTo')) {
            $query->whereDate('tanggal_pemeriksaan', '<=', $date);
        }
        if (in_array($r->query('jenis'), ['SPBU', 'INDUSTRI'], true)) {
            $query->where('jenis_kendaraan', $r->query('jenis'));
        }
        if (in_array($r->query('status'), ['draft', 'pending_hsse', 'signed_hsse', 'approved', 'rejected'], true)) {
            $query->where('status_approval', $r->query('status'));
        }
        $rows = $query->orderByDesc('tanggal_pemeriksaan')->get()->map(fn ($x) => [$x->id, $x->jenis_kendaraan, $x->nomor_polisi, $x->nama_transport, $x->tanggal_pemeriksaan, $x->ekim_valid_until, $x->status_approval]);
        $path = SimpleXlsx::create(['ID', 'Jenis', 'Nomor Polisi', 'Transportir', 'Tanggal Pemeriksaan', 'EKIM Berlaku', 'Status'], $rows);
        $this->audit($r, 'EXPORT', 'Export XLSX data checklist');

        return response()->download($path, 'data-checklist-'.today()->format('Ymd').'.xlsx', ['Content-Type' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'])->deleteFileAfterSend(true);
    }
}
