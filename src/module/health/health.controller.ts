import { Controller, Get, Head, Header, HttpCode } from '@nestjs/common';

/**
 * Lightweight reachability endpoint used by the mobile
 * `ConnectivityService` to distinguish a usable internet connection
 * from a captive portal / VPN-stuck-state. Intentionally:
 *
 *   * unauthenticated — the probe runs before login during cold start;
 *   * cheap — no DB call, no logging, no auth chain;
 *   * non-cacheable so each probe reflects current reachability.
 */
@Controller('health')
export class HealthController {
  /**
   * `HEAD /health` is the cheapest probe; it is excluded from the
   * global `/v1` prefix in `main.ts`.
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
