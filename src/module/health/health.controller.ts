import { Controller, Get, Head, Header, HttpCode } from '@nestjs/common';

/**
 * Lightweight reachability endpoint used by the mobile
 * `ConnectivityService` to distinguish a usable internet connection
 * from a captive portal / VPN-stuck-state. Intentionally:
 *
 *   * unauthenticated — the probe runs before login during cold start;
 *   * cheap — no DB call, no logging, no auth chain;
 *   * cacheable for at most a few seconds so an aggressive client can't
 *     accidentally DDoS itself through a stale cache.
 */
@Controller('health')
export class HealthController {
  /**
   * `HEAD /health` is the cheapest probe; we route it explicitly so
   * Express doesn't fall through to the catch-all and emit a 405.
   */
  @Head()
  @HttpCode(204)
  @Header('Cache-Control', 'no-store')
  head(): void {
    // 204 No Content: we don't carry a body anyway.
  }

  @Get()
  @Header('Cache-Control', 'no-store')
  get(): { ok: boolean; ts: string } {
    return { ok: true, ts: new Date().toISOString() };
  }
}
