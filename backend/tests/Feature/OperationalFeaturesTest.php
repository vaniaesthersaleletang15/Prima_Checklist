<?php

namespace Tests\Feature;

use App\Models\User;
use App\Services\RetentionService;
use Carbon\Carbon;
use Database\Seeders\DatabaseSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class OperationalFeaturesTest extends TestCase
{
    use RefreshDatabase;

    private function user(string $role, string $username): User
    {
        return User::create(['username' => $username, 'full_name' => ucfirst($username), 'email' => "$username@example.test", 'password' => 'Secret123!', 'role' => $role, 'status' => 'active']);
    }

    private function token(User $user, int $minutes = 20): string
    {
        return $user->createToken('test', ['*'], now()->addMinutes($minutes))->plainTextToken;
    }

    public function test_session_expiration_is_extended_after_authenticated_activity(): void
    {
        $user = $this->user('user', 'active_user');
        DB::table('system_settings')->insert(['setting_key' => 'session_timeout_minutes', 'setting_value' => '90', 'updated_at' => now()]);
        $token = $this->token($user);
        $tokenId = (int) str($token)->before('|')->toString();

        $this->withToken($token)->getJson('/api/v1/auth/me')->assertOk();

        $expiresAt = DB::table('personal_access_tokens')->where('id', $tokenId)->value('expires_at');
        $this->assertTrue(Carbon::parse($expiresAt)->greaterThan(now()->addMinutes(89)));
    }

    public function test_retention_removes_only_expired_audits_and_backups(): void
    {
        Storage::fake('local');
        DB::table('system_settings')->insert([
            ['setting_key' => 'audit_retention_days', 'setting_value' => '90', 'updated_at' => now()],
            ['setting_key' => 'backup_retention_days', 'setting_value' => '7', 'updated_at' => now()],
        ]);
        DB::table('audit_log')->insert([
            ['action' => 'OLD', 'created_at' => now()->subDays(91)],
            ['action' => 'CURRENT', 'created_at' => now()],
        ]);
        Storage::disk('local')->put('backups/old.dump', 'old');
        Storage::disk('local')->put('backups/old.dump.sha256', 'hash');
        Storage::disk('local')->put('backups/current.dump', 'current');
        touch(Storage::disk('local')->path('backups/old.dump'), now()->subDays(8)->timestamp);

        $result = app(RetentionService::class)->apply();

        $this->assertSame(1, $result['audit_deleted']);
        $this->assertSame(1, $result['backups_deleted']);
        $this->assertDatabaseMissing('audit_log', ['action' => 'OLD']);
        $this->assertDatabaseHas('audit_log', ['action' => 'CURRENT']);
        Storage::disk('local')->assertMissing('backups/old.dump');
        Storage::disk('local')->assertMissing('backups/old.dump.sha256');
        Storage::disk('local')->assertExists('backups/current.dump');
    }

    public function test_scheduler_uses_smtp_and_records_notification(): void
    {
        Mail::fake();
        $user = $this->user('admin', 'mail_admin');
        DB::table('system_settings')->insert([
            ['setting_key' => 'smtp_host', 'setting_value' => 'smtp.example.test', 'updated_at' => now()],
            ['setting_key' => 'smtp_port', 'setting_value' => '587', 'updated_at' => now()],
            ['setting_key' => 'smtp_encryption', 'setting_value' => 'tls', 'updated_at' => now()],
            ['setting_key' => 'smtp_username', 'setting_value' => 'mailer@example.test', 'updated_at' => now()],
            ['setting_key' => 'smtp_password', 'setting_value' => encrypt('secret'), 'updated_at' => now()],
            ['setting_key' => 'smtp_from_email', 'setting_value' => 'prima@example.test', 'updated_at' => now()],
            ['setting_key' => 'smtp_from_name', 'setting_value' => 'PRIMA', 'updated_at' => now()],
            ['setting_key' => 'notif_days_threshold', 'setting_value' => '30', 'updated_at' => now()],
        ]);
        DB::table('kendaraan')->insert(['jenis' => 'SPBU', 'nomor_polisi' => 'DB 1000 AA', 'merk_mobil' => 'Hino', 'nama_transport' => 'Transportir', 'email_kontraktor' => 'owner@example.test', 'status' => 'AKTIF', 'created_by' => $user->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('formulir_checklist')->insert(['jenis_kendaraan' => 'SPBU', 'nomor_polisi' => 'DB 1000 AA', 'nama_transport' => 'Transportir', 'tanggal_pemeriksaan' => today(), 'ekim_valid_until' => today()->addDays(5), 'status_approval' => 'approved', 'created_by' => $user->id, 'created_at' => now(), 'updated_at' => now()]);

        $this->artisan('prima:notifications')->assertSuccessful();

        $this->assertSame('smtp', config('mail.default'));
        $this->assertDatabaseHas('kim_notifications', ['nomor_polisi' => 'DB 1000 AA', 'email_to' => 'owner@example.test', 'status' => 'sent']);
    }

    public function test_scheduler_does_not_report_email_as_sent_without_smtp(): void
    {
        Mail::fake();
        $user = $this->user('admin', 'smtp_missing');
        DB::table('kendaraan')->insert(['jenis' => 'SPBU', 'nomor_polisi' => 'DB 1001 AA', 'merk_mobil' => 'Hino', 'nama_transport' => 'Transportir', 'email_kontraktor' => 'owner@example.test', 'status' => 'AKTIF', 'created_by' => $user->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('formulir_checklist')->insert(['jenis_kendaraan' => 'SPBU', 'nomor_polisi' => 'DB 1001 AA', 'nama_transport' => 'Transportir', 'tanggal_pemeriksaan' => today(), 'ekim_valid_until' => today()->subDay(), 'status_approval' => 'approved', 'created_by' => $user->id, 'created_at' => now(), 'updated_at' => now()]);

        $this->artisan('prima:notifications')->assertFailed();

        Mail::assertNothingSent();
        $this->assertDatabaseMissing('kim_notifications', ['nomor_polisi' => 'DB 1001 AA', 'status' => 'sent']);
        $this->assertDatabaseHas('system_settings', ['setting_key' => 'cron_last_status']);
    }

    public function test_vehicle_registration_normalizes_and_stores_transportir_email(): void
    {
        $user = $this->user('user', 'vehicle_registrar');
        $transportir = $this->user('pengurus', 'vehicle_owner');
        $payload = [
            'jenis' => 'SPBU',
            'nomor_polisi' => ' db 7777 zz ',
            'merk_mobil' => 'Hino 500',
            'tahun_kendaraan' => 2025,
            'nama_transport' => 'PT Transportir',
            'email_kontraktor' => ' OWNER@EXAMPLE.TEST ',
            'user_id_transportir' => $transportir->id,
        ];

        $this->withToken($this->token($user))->postJson('/api/v1/user-vehicles', $payload)->assertOk();

        $this->assertDatabaseHas('kendaraan', [
            'nomor_polisi' => 'DB 7777 ZZ',
            'email_kontraktor' => 'owner@example.test',
        ]);
        $this->assertDatabaseHas('pengurus_kendaraan', [
            'user_id' => $transportir->id,
            'nomor_polisi' => 'DB 7777 ZZ',
        ]);

        $this->app['auth']->forgetGuards();
        $this->withToken($this->token($user))->postJson('/api/v1/user-vehicles', $payload)
            ->assertUnprocessable()
            ->assertJsonPath('message', 'Nomor polisi DB 7777 ZZ sudah terdaftar. Gunakan nomor polisi lain atau minta SPV HSSE menetapkan kendaraan yang sudah ada ke akun transportir.');
    }

    public function test_master_vehicle_form_cannot_set_ekim_expiry_manually(): void
    {
        $admin = $this->user('admin', 'vehicle_admin');
        $transportir = $this->user('pengurus', 'master_vehicle_owner');

        $this->withToken($this->token($admin))->postJson('/api/v1/vehicles/manage', [
            'jenis' => 'SPBU',
            'nomor_polisi' => 'DB 8888 YY',
            'merk_mobil' => 'Hino 500',
            'nama_transport' => 'PT Transportir',
            'email_kontraktor' => 'owner@example.test',
            'user_id_transportir' => $transportir->id,
            'ekim_valid_until' => today()->addYear()->toDateString(),
            'status' => 'AKTIF',
        ])->assertOk();

        $this->assertDatabaseHas('kendaraan', [
            'nomor_polisi' => 'DB 8888 YY',
            'ekim_valid_until' => null,
        ]);
    }

    public function test_rejected_ekim_notifies_assigned_transportir(): void
    {
        $hsse = $this->user('hsse', 'reject_hsse');
        $transportir = $this->user('pengurus', 'reject_owner');
        DB::table('kendaraan')->insert(['jenis' => 'SPBU', 'nomor_polisi' => 'DB 9090 ZZ', 'merk_mobil' => 'Hino', 'status' => 'AKTIF', 'created_by' => $hsse->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('pengurus_kendaraan')->insert(['user_id' => $transportir->id, 'nomor_polisi' => 'DB 9090 ZZ', 'created_at' => now(), 'updated_at' => now()]);
        $formId = DB::table('formulir_checklist')->insertGetId(['jenis_kendaraan' => 'SPBU', 'nomor_polisi' => 'DB 9090 ZZ', 'tanggal_pemeriksaan' => today(), 'status_approval' => 'pending_hsse', 'created_by' => $hsse->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('checklist_items')->insert(['formulir_id' => $formId, 'item_number' => 1, 'item_name' => 'Rem', 'is_tidak' => true, 'keterangan' => 'Kampas rem aus']);

        $this->withToken($this->token($hsse))->postJson('/api/v1/checklists/workflow', [
            'formulir_id' => $formId,
            'action' => 'reject',
            'reason' => 'Dokumen belum lengkap',
        ])->assertOk()->assertJsonPath('data.new_status', 'rejected');

        $this->assertDatabaseHas('ekim_notifikasi', [
            'user_id' => $transportir->id,
            'formulir_id' => $formId,
            'nomor_polisi' => 'DB 9090 ZZ',
            'status' => 'rejected',
            'pesan' => 'E-KIM kendaraan DB 9090 ZZ tidak dapat diterbitkan. Alasan: Item Tidak Baik: Rem (Kampas rem aus). Catatan SPV HSSE: Dokumen belum lengkap',
        ]);
    }

    public function test_submitting_checklist_with_bad_item_notifies_transportir_automatically(): void
    {
        $hsse = $this->user('hsse', 'inspection_hsse');
        $transportir = $this->user('pengurus', 'inspection_owner');
        DB::table('kendaraan')->insert(['jenis' => 'SPBU', 'nomor_polisi' => 'DB 9191 ZZ', 'merk_mobil' => 'Hino', 'status' => 'AKTIF', 'created_by' => $hsse->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('pengurus_kendaraan')->insert(['user_id' => $transportir->id, 'nomor_polisi' => 'DB 9191 ZZ', 'created_at' => now(), 'updated_at' => now()]);
        $formId = DB::table('formulir_checklist')->insertGetId(['jenis_kendaraan' => 'SPBU', 'nomor_polisi' => 'DB 9191 ZZ', 'tanggal_pemeriksaan' => today(), 'status_approval' => 'draft', 'created_by' => $hsse->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('checklist_items')->insert(['formulir_id' => $formId, 'item_number' => 1, 'item_name' => 'STNK', 'is_tidak' => true, 'keterangan' => 'Masa berlaku habis']);

        $this->withToken($this->token($hsse))->postJson('/api/v1/checklists/workflow', [
            'formulir_id' => $formId,
            'action' => 'submit',
        ])->assertOk()
            ->assertJsonPath('data.new_status', 'rejected')
            ->assertJsonPath('data.reason', 'Item Tidak Baik: STNK (Masa berlaku habis)');

        $this->assertDatabaseHas('formulir_checklist', ['id' => $formId, 'status_approval' => 'rejected']);
        $this->assertDatabaseHas('ekim_notifikasi', [
            'user_id' => $transportir->id,
            'formulir_id' => $formId,
            'status' => 'rejected',
            'pesan' => 'E-KIM kendaraan DB 9191 ZZ tidak dapat diterbitkan. Alasan: Item Tidak Baik: STNK (Masa berlaku habis)',
        ]);
    }

    public function test_transportir_can_view_and_mark_only_their_ekim_notifications_as_read(): void
    {
        $owner = $this->user('pengurus', 'notification_owner');
        $other = $this->user('pengurus', 'notification_other');
        $ownerNotification = DB::table('ekim_notifikasi')->insertGetId(['user_id' => $owner->id, 'nomor_polisi' => 'DB 9393 ZZ', 'status' => 'issued', 'pesan' => 'E-KIM disetujui.', 'is_read' => false, 'created_at' => now()]);
        $otherNotification = DB::table('ekim_notifikasi')->insertGetId(['user_id' => $other->id, 'nomor_polisi' => 'DB 9494 ZZ', 'status' => 'rejected', 'pesan' => 'E-KIM ditolak.', 'is_read' => false, 'created_at' => now()]);

        $this->withToken($this->token($owner))->getJson('/api/v1/my-ekim-notifications')
            ->assertOk()
            ->assertJsonPath('data.unread_count', 1)
            ->assertJsonCount(1, 'data.notifications')
            ->assertJsonPath('data.notifications.0.id', $ownerNotification);

        $this->app['auth']->forgetGuards();
        $this->withToken($this->token($owner))->postJson('/api/v1/my-ekim-notifications/read', ['id' => $otherNotification])
            ->assertOk()
            ->assertJsonPath('data.updated', 0);
        $this->assertDatabaseHas('ekim_notifikasi', ['id' => $otherNotification, 'is_read' => false]);

        $this->app['auth']->forgetGuards();
        $this->withToken($this->token($owner))->postJson('/api/v1/my-ekim-notifications/read', ['id' => $ownerNotification])
            ->assertOk()
            ->assertJsonPath('data.updated', 1);
        $this->assertDatabaseHas('ekim_notifikasi', ['id' => $ownerNotification, 'is_read' => true]);
    }

    public function test_manager_approval_history_contains_only_checklists_signed_by_that_manager(): void
    {
        $manager = $this->user('manager_hsse', 'history_manager');
        $otherManager = $this->user('manager_hsse', 'other_history_manager');
        $creator = $this->user('hsse', 'history_hsse');

        $ownedId = DB::table('formulir_checklist')->insertGetId([
            'jenis_kendaraan' => 'SPBU',
            'nomor_polisi' => 'DB 1111 AA',
            'nama_transport' => 'PT Satu',
            'tanggal_pemeriksaan' => today(),
            'status_approval' => 'approved',
            'created_by' => $creator->id,
            'ttd_manajer_user_id' => $manager->id,
            'ttd_manajer_nama' => $manager->full_name,
            'ttd_manajer_timestamp' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('formulir_checklist')->insert([
            'jenis_kendaraan' => 'INDUSTRI',
            'nomor_polisi' => 'DB 2222 BB',
            'nama_transport' => 'PT Dua',
            'tanggal_pemeriksaan' => today(),
            'status_approval' => 'approved',
            'created_by' => $creator->id,
            'ttd_manajer_user_id' => $otherManager->id,
            'ttd_manajer_nama' => $otherManager->full_name,
            'ttd_manajer_timestamp' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->withToken($this->token($manager))
            ->getJson('/api/v1/checklists?signedByMe=1&limit=100')
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.id', $ownedId)
            ->assertJsonPath('data.0.nomor_polisi', 'DB 1111 AA');
    }

    public function test_export_returns_a_real_xlsx_archive(): void
    {
        if (! class_exists(\ZipArchive::class)) {
            $this->markTestSkipped('Ekstensi ZIP tidak tersedia.');
        }
        $admin = $this->user('admin', 'export_admin');
        DB::table('formulir_checklist')->insert(['jenis_kendaraan' => 'SPBU', 'nomor_polisi' => 'DB 2000 BB', 'tanggal_pemeriksaan' => today(), 'ekim_valid_until' => today()->addYear(), 'status_approval' => 'approved', 'created_by' => $admin->id, 'created_at' => now(), 'updated_at' => now()]);

        $response = $this->withToken($this->token($admin))->get('/api/v1/export/checklists?jenis=SPBU');

        $response->assertOk()->assertHeader('content-type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        $this->assertStringContainsString('.xlsx', (string) $response->headers->get('content-disposition'));
        $zip = new \ZipArchive;
        $this->assertTrue($zip->open($response->baseResponse->getFile()->getPathname()));
        $this->assertNotFalse($zip->locateName('[Content_Types].xml'));
        $this->assertNotFalse($zip->locateName('xl/worksheets/sheet1.xml'));
        $zip->close();
    }

    public function test_document_upload_is_limited_to_assigned_pengurus(): void
    {
        Storage::fake('private');
        $owner = $this->user('pengurus', 'owner');
        $other = $this->user('pengurus', 'other');
        DB::table('kendaraan')->insert(['jenis' => 'SPBU', 'nomor_polisi' => 'DB 3000 CC', 'merk_mobil' => 'Hino', 'status' => 'AKTIF', 'created_at' => now(), 'updated_at' => now()]);
        DB::table('pengurus_kendaraan')->insert(['user_id' => $owner->id, 'nomor_polisi' => 'DB 3000 CC', 'created_at' => now(), 'updated_at' => now()]);
        $payload = ['jenis_dokumen' => 'STNK', 'nomor_polisi' => 'DB 3000 CC', 'tanggal_berlaku' => today()->addYear()->toDateString(), 'file' => UploadedFile::fake()->create('stnk.pdf', 10, 'application/pdf')];

        $this->withToken($this->token($other))->post('/api/v1/documents', $payload, ['Accept' => 'application/json'])->assertForbidden();
        $this->app['auth']->forgetGuards();
        $this->withToken($this->token($owner))->post('/api/v1/documents', $payload, ['Accept' => 'application/json'])->assertOk();
        $this->assertDatabaseHas('dokumen_kendaraan', ['nomor_polisi' => 'DB 3000 CC', 'uploaded_by' => $owner->id, 'status' => 'PENDING']);
    }

    public function test_approved_document_updates_vehicle_expiry_and_draft_checklist_only(): void
    {
        $admin = $this->user('admin', 'document_reviewer');
        $owner = $this->user('pengurus', 'document_owner');
        $expiry = today()->addYear()->toDateString();
        $oldExpiry = today()->addMonths(2)->toDateString();
        DB::table('kendaraan')->insert(['jenis' => 'SPBU', 'nomor_polisi' => 'DB 3111 CC', 'merk_mobil' => 'Hino', 'status' => 'AKTIF', 'created_at' => now(), 'updated_at' => now()]);
        $draftId = DB::table('formulir_checklist')->insertGetId(['jenis_kendaraan' => 'SPBU', 'nomor_polisi' => 'DB 3111 CC', 'tanggal_pemeriksaan' => today(), 'status_approval' => 'draft', 'created_at' => now(), 'updated_at' => now()]);
        $approvedId = DB::table('formulir_checklist')->insertGetId(['jenis_kendaraan' => 'SPBU', 'nomor_polisi' => 'DB 3111 CC', 'tanggal_pemeriksaan' => today(), 'status_approval' => 'approved', 'created_at' => now(), 'updated_at' => now()]);
        DB::table('checklist_items')->insert([
            ['formulir_id' => $draftId, 'item_number' => 1, 'item_name' => 'STNK', 'tanggal_expire' => $oldExpiry],
            ['formulir_id' => $approvedId, 'item_number' => 1, 'item_name' => 'STNK', 'tanggal_expire' => $oldExpiry],
        ]);
        $documentId = DB::table('dokumen_kendaraan')->insertGetId(['nomor_polisi' => 'DB 3111 CC', 'jenis_dokumen' => 'STNK', 'tanggal_berlaku' => $expiry, 'uploaded_by' => $owner->id, 'status' => 'PENDING', 'created_at' => now(), 'updated_at' => now()]);

        $token = $this->token($admin);
        $this->withToken($token)->postJson("/api/v1/documents/$documentId/review", ['action' => 'approve'])
            ->assertOk()
            ->assertJsonPath('data.updated_draft_items', 1);

        $this->assertDatabaseHas('dokumen_kendaraan', ['id' => $documentId, 'status' => 'DISETUJUI']);
        $this->assertDatabaseHas('checklist_items', ['formulir_id' => $draftId, 'item_name' => 'STNK', 'tanggal_expire' => $expiry]);
        $this->assertDatabaseHas('checklist_items', ['formulir_id' => $approvedId, 'item_name' => 'STNK', 'tanggal_expire' => $oldExpiry]);

        $this->app['auth']->forgetGuards();
        $this->withToken($this->token($admin))->getJson('/api/v1/vehicles')
            ->assertOk()
            ->assertJsonPath('data.0.approved_document_expiries.STNK', $expiry);
    }

    public function test_seeder_never_overwrites_an_existing_admin_password(): void
    {
        $admin = $this->user('admin', 'admin');
        $originalHash = $admin->password;

        $this->seed(DatabaseSeeder::class);

        $this->assertSame($originalHash, $admin->fresh()->password);
    }

    public function test_admin_can_delete_user_without_deleting_business_history(): void
    {
        $admin = $this->user('admin', 'delete_admin');
        $target = $this->user('pengurus', 'deleted_pengurus');
        $targetToken = $this->token($target);
        DB::table('kendaraan')->insert(['jenis' => 'SPBU', 'nomor_polisi' => 'DB 4000 DD', 'merk_mobil' => 'Hino', 'status' => 'AKTIF', 'created_by' => $target->id, 'created_at' => now(), 'updated_at' => now()]);
        DB::table('pengurus_kendaraan')->insert(['user_id' => $target->id, 'nomor_polisi' => 'DB 4000 DD', 'created_at' => now(), 'updated_at' => now()]);
        DB::table('formulir_checklist')->insert(['jenis_kendaraan' => 'SPBU', 'nomor_polisi' => 'DB 4000 DD', 'tanggal_pemeriksaan' => today(), 'status_approval' => 'draft', 'created_by' => $target->id, 'created_at' => now(), 'updated_at' => now()]);

        $this->withToken($this->token($admin))->deleteJson("/api/v1/users/{$target->id}")
            ->assertOk()
            ->assertJsonPath('message', 'Pengguna berhasil dihapus.');

        $this->assertDatabaseMissing('users', ['id' => $target->id]);
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => (int) str($targetToken)->before('|')->toString()]);
        $this->assertDatabaseMissing('pengurus_kendaraan', ['user_id' => $target->id]);
        $this->assertDatabaseHas('kendaraan', ['nomor_polisi' => 'DB 4000 DD', 'created_by' => null]);
        $this->assertDatabaseHas('formulir_checklist', ['nomor_polisi' => 'DB 4000 DD', 'created_by' => null]);
        $this->assertDatabaseHas('audit_log', ['action' => 'USER_DELETE', 'user_name' => $admin->username]);
    }

    public function test_admin_cannot_delete_current_or_primary_admin_account(): void
    {
        $admin = $this->user('admin', 'security_admin');
        $primary = $this->user('admin', 'admin');
        $token = $this->token($admin);

        $this->withToken($token)->deleteJson("/api/v1/users/{$admin->id}")->assertStatus(409);
        $this->withToken($token)->deleteJson("/api/v1/users/{$primary->id}")->assertStatus(409);

        $this->assertDatabaseHas('users', ['id' => $admin->id]);
        $this->assertDatabaseHas('users', ['id' => $primary->id]);
    }
}
