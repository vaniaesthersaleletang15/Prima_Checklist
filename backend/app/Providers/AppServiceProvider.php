<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        RateLimiter::for('login', fn (Request $request) => Limit::perMinute(5)->by(strtolower((string) $request->input('email')).'|'.$request->ip()));
        RateLimiter::for('password-reset-request', fn (Request $request) => Limit::perMinute(5)
            ->by(strtolower(trim((string) $request->input('email'))).'|'.$request->ip())
            ->response(fn (Request $request, array $headers) => response()->json([
                'success' => false,
                'message' => 'Terlalu banyak permintaan reset. Silakan tunggu satu menit lalu coba kembali.',
                'data' => null,
            ], 429, $headers)));
        RateLimiter::for('password-reset-confirm', fn (Request $request) => Limit::perMinute(10)
            ->by(strtolower(trim((string) $request->input('email'))).'|'.$request->ip())
            ->response(fn (Request $request, array $headers) => response()->json([
                'success' => false,
                'message' => 'Terlalu banyak percobaan. Silakan tunggu satu menit lalu coba kembali.',
                'data' => null,
            ], 429, $headers)));
    }
}
