<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        User::firstOrCreate(
            ['username' => env('PRIMA_ADMIN_USERNAME', 'admin')],
            [
                'full_name' => env('PRIMA_ADMIN_NAME', 'SPV HSSE IT Bitung'),
                'email' => env('PRIMA_ADMIN_EMAIL', 'admin@pertamina.com'),
                'department' => 'HSSE',
                'position' => 'SPV HSSE',
                'password' => Hash::make(env('PRIMA_ADMIN_PASSWORD', 'ChangeMe-Immediately!')),
                'role' => 'admin',
                'status' => 'active',
            ]
        );

        $managerEmail = strtolower(trim((string) env('PRIMA_MANAGER_EMAIL', '')));
        $managerPassword = (string) env('PRIMA_MANAGER_PASSWORD', '');
        if (! User::where('role', 'manager_hsse')->exists() && $managerEmail !== '' && $managerPassword !== '') {
            User::create([
                'username' => env('PRIMA_MANAGER_USERNAME', 'manager'),
                'full_name' => env('PRIMA_MANAGER_NAME', 'Integrated Terminal Manager'),
                'email' => $managerEmail,
                'department' => 'Management',
                'position' => 'Integrated Terminal Manager',
                'password' => Hash::make($managerPassword),
                'role' => 'manager_hsse',
                'status' => 'active',
            ]);
        }

        if (app()->environment('local')) {
            $now = now();
            DB::table('system_settings')->insertOrIgnore([
                ['setting_key' => 'smtp_host', 'setting_value' => 'mailpit', 'updated_at' => $now],
                ['setting_key' => 'smtp_port', 'setting_value' => '1025', 'updated_at' => $now],
                ['setting_key' => 'smtp_encryption', 'setting_value' => 'none', 'updated_at' => $now],
                ['setting_key' => 'smtp_username', 'setting_value' => '', 'updated_at' => $now],
                ['setting_key' => 'smtp_from_email', 'setting_value' => 'no-reply@prima.local', 'updated_at' => $now],
                ['setting_key' => 'smtp_from_name', 'setting_value' => 'PRIMA E-KIM', 'updated_at' => $now],
                ['setting_key' => 'notif_days_threshold', 'setting_value' => '30', 'updated_at' => $now],
            ]);
        }
    }
}
