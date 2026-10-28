<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

class PrimaApiTest extends TestCase
{
    use RefreshDatabase;

    private function login(string $role = 'admin', string $username = 'tester'): array
    {
        User::create(['username' => $username, 'full_name' => ucfirst($username), 'email' => "$username@example.test", 'password' => 'Secret123!', 'role' => $role, 'status' => 'active']);
        $portal = $role === 'pengurus' ? 'transportir' : 'internal';
        $response = $this->postJson('/api/v1/auth/login', ['email' => "$username@example.test", 'password' => 'Secret123!', 'portal' => $portal])->assertOk()->assertJsonPath('success', true);

        return [$response->json('data.user'), $response->json('data.token')];
    }

    public function test_authentication_registration_and_role_protection(): void
    {
        $this->postJson('/api/v1/auth/register', ['email' => 'baru@example.test', 'password' => 'Strong123!', 'full_name' => 'Pengguna Baru', 'phone' => '08123', 'reason' => 'Operasional', 'requested_role' => 'pengurus', 'portal' => 'transportir'])->assertOk();
        $this->assertDatabaseHas('user_registrations', ['email' => 'baru@example.test', 'status' => 'pending']);
        [, $token] = $this->login('user');
        $this->withToken($token)->getJson('/api/v1/auth/me')->assertOk()->assertJsonPath('data.role', 'user');
        $this->withToken($token)->getJson('/api/v1/users')->assertForbidden();
    }

    public function test_login_requires_server_verified_captcha_when_enabled(): void
    {
        config()->set('services.turnstile.enabled', true);
        config()->set('services.turnstile.site_key', 'test-site-key');
        config()->set('services.turnstile.secret_key', 'test-secret-key');
        User::create(['username' => 'captcha_user', 'full_name' => 'Captcha User', 'email' => 'captcha@example.test', 'password' => 'Secret123!', 'role' => 'user', 'status' => 'active']);

        $this->getJson('/api/v1/auth/captcha-config')
            ->assertOk()
            ->assertJsonPath('data.enabled', true)
            ->assertJsonPath('data.site_key', 'test-site-key');

        $this->postJson('/api/v1/auth/login', ['email' => 'captcha@example.test', 'password' => 'Secret123!', 'portal' => 'internal'])
            ->assertStatus(422);

        Http::fake([
            'challenges.cloudflare.com/*' => Http::response(['success' => true, 'action' => 'login', 'hostname' => 'localhost']),
        ]);

        $this->postJson('/api/v1/auth/login', ['email' => 'captcha@example.test', 'password' => 'Secret123!', 'portal' => 'internal', 'captcha_token' => 'valid-test-token'])
            ->assertOk()
            ->assertJsonPath('data.user.email', 'captcha@example.test')
            ->assertJsonMissingPath('data.user.username');

        Http::assertSent(fn ($request) => $request['secret'] === 'test-secret-key' && $request['response'] === 'valid-test-token');
    }

    public function test_login_fails_closed_when_captcha_provider_rejects_token(): void
    {
        config()->set('services.turnstile.enabled', true);
        config()->set('services.turnstile.secret_key', 'test-secret-key');
        User::create(['username' => 'blocked_bot', 'full_name' => 'Blocked Bot', 'email' => 'bot@example.test', 'password' => 'Secret123!', 'role' => 'user', 'status' => 'active']);
        Http::fake([
            'challenges.cloudflare.com/*' => Http::response(['success' => false, 'error-codes' => ['invalid-input-response']]),
        ]);

        $this->postJson('/api/v1/auth/login', ['email' => 'bot@example.test', 'password' => 'Secret123!', 'portal' => 'internal', 'captcha_token' => 'invalid-token'])
            ->assertStatus(422)
            ->assertJsonPath('success', false);

        $this->assertDatabaseCount('personal_access_tokens', 0);
    }

    public function test_login_portals_enforce_internal_and_transportir_roles(): void
    {
        User::create(['username' => 'internal_user', 'full_name' => 'Internal User', 'email' => 'internal@example.test', 'password' => 'Secret123!', 'role' => 'hsse', 'status' => 'active']);
        User::create(['username' => 'external_user', 'full_name' => 'External User', 'email' => 'external@example.test', 'password' => 'Secret123!', 'role' => 'pengurus', 'status' => 'active']);

        $this->postJson('/api/v1/auth/login', ['email' => 'internal@example.test', 'password' => 'Secret123!', 'portal' => 'transportir'])
            ->assertForbidden()
            ->assertJsonPath('success', false);
        $this->postJson('/api/v1/auth/login', ['email' => 'external@example.test', 'password' => 'Secret123!', 'portal' => 'internal'])
            ->assertForbidden()
            ->assertJsonPath('success', false);
        $this->assertDatabaseCount('personal_access_tokens', 0);

        $this->postJson('/api/v1/auth/login', ['email' => 'internal@example.test', 'password' => 'Secret123!', 'portal' => 'internal'])
            ->assertOk()
            ->assertJsonPath('data.user.role', 'hsse');
        $this->postJson('/api/v1/auth/login', ['email' => 'external@example.test', 'password' => 'Secret123!', 'portal' => 'transportir'])
            ->assertOk()
            ->assertJsonPath('data.user.role', 'pengurus');
    }

    public function test_public_registration_cannot_request_internal_role(): void
    {
        $payload = ['email' => 'manager-request@example.test', 'password' => 'Strong123!', 'full_name' => 'Manager Request', 'phone' => '08123', 'reason' => 'Operasional', 'requested_role' => 'manager_hsse', 'portal' => 'transportir'];

        $this->postJson('/api/v1/auth/register', $payload)->assertStatus(422);
        $this->assertDatabaseMissing('user_registrations', ['email' => 'manager-request@example.test']);
    }

    public function test_internal_public_registration_is_disabled(): void
    {
        $payload = ['email' => 'manager-request@example.test', 'password' => 'Strong123!', 'full_name' => 'Manager HSSE', 'phone' => '08124', 'reason' => 'Persetujuan checklist', 'requested_role' => 'manager_hsse', 'portal' => 'internal'];

        $this->postJson('/api/v1/auth/register', $payload)->assertStatus(422);
        $this->assertDatabaseMissing('user_registrations', ['email' => 'manager-request@example.test']);
    }

    public function test_internal_registration_rejects_hsse_self_registration(): void
    {
        $payload = ['email' => 'hsse-request@example.test', 'password' => 'Strong123!', 'full_name' => 'Anggota HSSE', 'phone' => '08124', 'reason' => 'Pemeriksaan kendaraan', 'requested_role' => 'hsse', 'portal' => 'internal'];

        $this->postJson('/api/v1/auth/register', $payload)->assertStatus(422);
        $this->assertDatabaseMissing('user_registrations', ['email' => 'hsse-request@example.test']);
    }

    public function test_spv_can_create_hsse_and_transportir_accounts_directly(): void
    {
        [, $token] = $this->login('admin', 'spv_creator');
        $base = ['password' => 'Strong123!', 'phone' => '08125'];

        $this->withToken($token)->postJson('/api/v1/users', $base + ['full_name' => 'Petugas HSSE Baru', 'email' => 'new-hsse@example.test', 'role' => 'hsse'])
            ->assertCreated()
            ->assertJsonPath('data.role', 'hsse');
        $this->withToken($token)->postJson('/api/v1/users', $base + ['full_name' => 'Transportir Baru', 'email' => 'new-transporter@example.test', 'role' => 'pengurus'])
            ->assertCreated()
            ->assertJsonPath('data.role', 'pengurus');

        $this->assertDatabaseHas('users', ['email' => 'new-hsse@example.test', 'role' => 'hsse', 'status' => 'active']);
        $this->assertDatabaseHas('users', ['email' => 'new-transporter@example.test', 'role' => 'pengurus', 'status' => 'active']);
    }

    public function test_spv_can_change_own_and_manager_email(): void
    {
        [$spv, $token] = $this->login('admin', 'spv_email_editor');
        $manager = User::create(['username' => 'manager_email_editor', 'full_name' => 'Manager', 'email' => 'manager-old@example.test', 'password' => 'Secret123!', 'role' => 'manager_hsse', 'status' => 'active']);

        $this->withToken($token)->putJson("/api/v1/users/{$spv['id']}", ['full_name' => $spv['full_name'], 'email' => 'spv-new@example.test', 'role' => 'admin'])
            ->assertOk();
        $this->withToken($token)->putJson("/api/v1/users/{$manager->id}", ['full_name' => $manager->full_name, 'email' => 'manager-new@example.test', 'role' => 'manager_hsse'])
            ->assertOk();

        $this->assertDatabaseHas('users', ['id' => $spv['id'], 'email' => 'spv-new@example.test']);
        $this->assertDatabaseHas('users', ['id' => $manager->id, 'email' => 'manager-new@example.test']);
    }

    public function test_spv_cannot_assign_protected_or_legacy_roles_from_user_management(): void
    {
        [, $token] = $this->login('admin', 'spv_role_guard');
        $hsse = User::create(['username' => 'role_guard_hsse', 'full_name' => 'Petugas HSSE', 'email' => 'role-guard@example.test', 'password' => 'Secret123!', 'role' => 'hsse', 'status' => 'active']);

        foreach (['admin', 'manager_hsse', 'user'] as $forbiddenRole) {
            $this->withToken($token)->putJson("/api/v1/users/{$hsse->id}", [
                'full_name' => $hsse->full_name,
                'email' => $hsse->email,
                'role' => $forbiddenRole,
            ])->assertStatus(422);
        }

        $this->withToken($token)->putJson("/api/v1/users/{$hsse->id}", [
            'full_name' => $hsse->full_name,
            'email' => $hsse->email,
            'role' => 'pengurus',
        ])->assertOk();

        $this->assertDatabaseHas('users', ['id' => $hsse->id, 'role' => 'pengurus']);
    }

    public function test_spv_and_manager_roles_are_locked_during_profile_updates(): void
    {
        [$spv, $token] = $this->login('admin', 'spv_locked_role');
        $manager = User::create(['username' => 'manager_locked_role', 'full_name' => 'Manager', 'email' => 'manager-locked@example.test', 'password' => 'Secret123!', 'role' => 'manager_hsse', 'status' => 'active']);

        $this->withToken($token)->putJson("/api/v1/users/{$spv['id']}", [
            'full_name' => $spv['full_name'],
            'email' => $spv['email'],
            'role' => 'hsse',
        ])->assertStatus(422);
        $this->withToken($token)->putJson("/api/v1/users/{$manager->id}", [
            'full_name' => $manager->full_name,
            'email' => $manager->email,
            'role' => 'pengurus',
        ])->assertStatus(422);

        $this->assertDatabaseHas('users', ['id' => $spv['id'], 'role' => 'admin']);
        $this->assertDatabaseHas('users', ['id' => $manager->id, 'role' => 'manager_hsse']);
    }

    public function test_transportir_can_reset_password_with_one_time_token(): void
    {
        $user = User::create(['username' => 'forgot_owner', 'full_name' => 'Forgot Owner', 'email' => 'forgot-owner@example.test', 'password' => 'OldSecret123!', 'role' => 'pengurus', 'status' => 'active']);
        $oldToken = $user->createToken('old-session')->plainTextToken;
        DB::table('password_reset_tokens')->insert([
            'email' => $user->email,
            'token' => Hash::make('valid-reset-token'),
            'created_at' => now(),
        ]);
        $payload = [
            'email' => $user->email,
            'token' => 'valid-reset-token',
            'password' => 'NewSecret123!',
            'password_confirmation' => 'NewSecret123!',
        ];

        $this->postJson('/api/v1/auth/reset-password', $payload)
            ->assertOk()
            ->assertJsonPath('success', true);
        $this->assertTrue(Hash::check('NewSecret123!', $user->fresh()->password));
        $this->assertDatabaseMissing('password_reset_tokens', ['email' => $user->email]);
        $this->assertDatabaseMissing('personal_access_tokens', ['token' => hash('sha256', $oldToken)]);
        $this->postJson('/api/v1/auth/reset-password', $payload)->assertStatus(422);
    }

    public function test_forgot_password_does_not_reveal_unknown_or_internal_accounts(): void
    {
        User::create(['username' => 'internal_forgot', 'full_name' => 'Internal', 'email' => 'internal-forgot@example.test', 'password' => 'Secret123!', 'role' => 'hsse', 'status' => 'active']);

        foreach (['unknown@example.test', 'internal-forgot@example.test'] as $email) {
            $this->postJson('/api/v1/auth/forgot-password', ['email' => $email])
                ->assertOk()
                ->assertJsonPath('message', 'Jika email terdaftar sebagai akun transportir, tautan reset password akan dikirim.');
        }
        $this->assertDatabaseCount('password_reset_tokens', 0);
    }

    public function test_forgot_password_rate_limit_returns_indonesian_message(): void
    {
        $payload = ['email' => 'rate-limit-reset@example.test'];
        for ($attempt = 1; $attempt <= 5; $attempt++) {
            $this->postJson('/api/v1/auth/forgot-password', $payload)->assertOk();
        }

        $this->postJson('/api/v1/auth/forgot-password', $payload)
            ->assertStatus(429)
            ->assertJsonPath('message', 'Terlalu banyak permintaan reset. Silakan tunggu satu menit lalu coba kembali.');
    }

    public function test_transportir_cannot_access_internal_checklist_or_export_endpoints(): void
    {
        [, $token] = $this->login('pengurus', 'external_access');

        $this->withToken($token)->getJson('/api/v1/checklists')->assertForbidden();
        $this->withToken($token)->getJson('/api/v1/export/checklists')->assertForbidden();
    }

    public function test_checklist_can_be_saved_signed_and_verified(): void
    {
        [$admin,$adminToken] = $this->login('admin', 'admin_test');
        [$manager,$managerToken] = $this->login('manager_hsse', 'manager_test');
        [$transportir] = $this->login('pengurus', 'owner_test');
        $vehicleId = DB::table('kendaraan')->insertGetId(['jenis' => 'SPBU', 'nomor_polisi' => 'DB 1234 AB', 'merk_mobil' => 'Hino', 'tahun_kendaraan' => 2025, 'status' => 'AKTIF', 'created_by' => $admin['id'], 'created_at' => now(), 'updated_at' => now()]);
        DB::table('pengurus_kendaraan')->insert(['user_id' => $transportir['id'], 'nomor_polisi' => 'DB 1234 AB', 'created_at' => now(), 'updated_at' => now()]);
        $payload = ['selectedVehicleId' => $vehicleId, 'jenisKendaraan' => 'SPBU', 'nomorUrut' => '001', 'tanggalPemeriksaan' => today()->toDateString(), 'ekimValidUntil' => today()->addYear()->toDateString(), 'statusGate' => 'OK', 'statusUpload' => 'OK', 'namaPemeriksaBagian' => 'Admin_test', 'tanggalPemeriksaBagian' => today()->toDateString(), 'checklist' => [['nama' => 'Safety switch', 'baik' => true, 'tidak' => false, 'keterangan' => 'Baik', 'tanggal_expire' => '']]];
        $id = $this->withToken($adminToken)->postJson('/api/v1/checklists', $payload)->assertOk()->json('data.id');
        $signature = ['formulir_id' => $id, 'role' => 'hsse', 'canvas_image' => 'data:image/png;base64,iVBORw0KGgo=', 'signer_name' => 'Admin_test'];
        $this->withToken($adminToken)->postJson('/api/v1/checklists/signature', $signature)->assertOk()->assertJsonPath('data.new_status', 'signed_hsse');
        $this->app['auth']->forgetGuards();
        $this->withToken($managerToken)->postJson('/api/v1/checklists/signature', ['formulir_id' => $id, 'role' => 'manajer', 'canvas_image' => 'data:image/png;base64,iVBORw0KGgo=', 'signer_name' => 'Manager_test'])->assertOk()->assertJsonPath('data.new_status', 'approved');
        $this->assertDatabaseHas('kendaraan', ['id' => $vehicleId, 'ekim_valid_until' => today()->addYear()->toDateString(), 'tanggal_pemeriksaan_terakhir' => today()->toDateString()]);
        $this->assertDatabaseHas('ekim_notifikasi', ['user_id' => $transportir['id'], 'formulir_id' => $id, 'status' => 'issued']);
        $uuid = DB::table('formulir_checklist')->where('id', $id)->value('verification_uuid');
        $this->getJson("/api/v1/verify/$uuid")->assertOk()->assertJsonPath('data.validation.authentic', true);
    }
}
