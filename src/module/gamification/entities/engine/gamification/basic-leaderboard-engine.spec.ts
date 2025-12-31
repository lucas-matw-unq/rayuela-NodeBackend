import { PointsFirstLBEngine } from './basic-leaderboard-engine';
import { LeaderboardStrategy } from '../../../../project/dto/create-project.dto';

describe('PointsFirstLBEngine', () => {
    let engine: PointsFirstLBEngine;

    beforeEach(() => {
        engine = new PointsFirstLBEngine();
    });

    it('should be assignable to POINTS_FIRST strategy', () => {
        const project = { leaderboardStrategy: LeaderboardStrategy.POINTS_FIRST } as any;
        expect(engine.assignableTo(project)).toBe(true);
    });

    it('should sort users by points', () => {
        const project = { id: 'p1' } as any;
        const user1 = {
            id: 'u1',
            username: 'user1',
            getGameProfileFromProject: jest.fn().mockReturnValue({ points: 10, badges: [] }),
        } as any;
        const user2 = {
            id: 'u2',
            username: 'user2',
            getGameProfileFromProject: jest.fn().mockReturnValue({ points: 20, badges: [] }),
        } as any;
        const currentUser = user1;

        const result = engine.build([user1, user2], currentUser, project);
        expect(result[0]._id).toBe('u2');
        expect(result[1]._id).toBe('u1');
    });
});
