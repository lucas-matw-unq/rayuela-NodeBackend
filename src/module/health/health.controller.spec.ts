import { HealthController } from './health.controller';

describe('HealthController', () => {
  let controller: HealthController;

  beforeEach(() => {
    controller = new HealthController();
  });

  it('GET /health returns ok=true plus a timestamp', () => {
    const res = controller.get();
    expect(res.ok).toBe(true);
    expect(typeof res.ts).toBe('string');
    // Loose ISO-8601 check — DateTime.parse on the client would accept this.
    expect(res.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('HEAD /health returns void (204 carried by the decorator)', () => {
    expect(controller.head()).toBeUndefined();
  });
});
