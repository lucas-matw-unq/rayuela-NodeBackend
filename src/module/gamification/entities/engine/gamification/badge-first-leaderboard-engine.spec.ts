import { BadgesFirstLBEngine } from './badge-first-leaderboard-engine';
import { GamificationStrategy } from '../../../../project/dto/create-project.dto';

describe('BadgesFirstLBEngine', () => {
  let engine: BadgesFirstLBEngine;

  beforeEach(() => {
    engine = new BadgesFirstLBEngine();
  });

  it('should be assignable to BASIC strategy', () => {
    const project = { gamificationStrategy: GamificationStrategy.BASIC } as any;
    expect(engine.assignableTo(project)).toBe(true);
  });

  it('should sort users by badges then points', () => {
    const project = { id: 'p1' } as any;
    const user1 = {
      id: 'u1',
      username: 'user1',
      getGameProfileFromProject: jest
        .fn()
        .mockReturnValue({ points: 10, badges: ['b1'] }),
    } as any;
    const user2 = {
      id: 'u2',
      username: 'user2',
      getGameProfileFromProject: jest
        .fn()
        .mockReturnValue({ points: 20, badges: ['b1', 'b2'] }),
    } as any;
    const user3 = {
      id: 'u3',
      username: 'user3',
      getGameProfileFromProject: jest
        .fn()
        .mockReturnValue({ points: 30, badges: ['b1'] }),
    } as any;
    const currentUser = user1;

    const result = engine.build([user1, user2, user3], currentUser, project);
    // user2 has 2 badges (highest)
    // user3 has 1 badge, 30 points
    // user1 has 1 badge, 10 points
    expect(result[0]._id).toBe('u2');
    expect(result[1]._id).toBe('u3');
    expect(result[2]._id).toBe('u1');
  });
});
