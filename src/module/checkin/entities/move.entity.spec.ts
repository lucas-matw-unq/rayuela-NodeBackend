import { Move, ScoreRate } from './move.entity';

describe('Move Entity', () => {
  it('should test getters', () => {
    const checkin = { id: 'c1' } as any;
    const gameStatus = { newPoints: 10 } as any;
    const move = new Move(checkin, gameStatus);

    expect(move.checkin).toBe(checkin);
    expect(move.gameStatus).toBe(gameStatus);
    expect(move.score).toBe(ScoreRate.NO_RATE);
    expect(move.timestamp).toBeDefined();
  });
});
