<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('pengurus_kendaraan', 'updated_at')) {
            Schema::table('pengurus_kendaraan', function (Blueprint $table) {
                $table->timestamp('updated_at')->nullable();
            });
        }
    }

    public function down(): void
    {
        if (Schema::hasColumn('pengurus_kendaraan', 'updated_at')) {
            Schema::table('pengurus_kendaraan', function (Blueprint $table) {
                $table->dropColumn('updated_at');
            });
        }
    }
};
