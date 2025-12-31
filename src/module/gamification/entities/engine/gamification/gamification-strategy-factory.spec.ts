import { Test, TestingModule } from '@nestjs/testing';
import { GamificationEngineFactory } from './gamification-strategy-factory';
import { BasicPointsEngine } from './basic-points-engine';
import { ElasticPointsEngine } from './elastic-points-engine';
import { PointsFirstLBEngine } from './basic-leaderboard-engine';
import { BadgesFirstLBEngine } from './badge-first-leaderboard-engine';
import { BasicBadgeEngine } from './basic-badge-engine';
import { GamificationStrategy, LeaderboardStrategy } from '../../../../project/dto/create-project.dto';

describe('GamificationEngineFactory', () => {
    let factory: GamificationEngineFactory;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                GamificationEngineFactory,
                { provide: BasicPointsEngine, useValue: {} },
                { provide: ElasticPointsEngine, useValue: {} },
                { provide: PointsFirstLBEngine, useValue: {} },
                { provide: BadgesFirstLBEngine, useValue: {} },
                { provide: BasicBadgeEngine, useValue: {} },
            ],
        }).compile();

        factory = module.get<GamificationEngineFactory>(GamificationEngineFactory);
    });

    it('should return correct engines', () => {
        expect(factory.getBadgeEngine(GamificationStrategy.BASIC)).toBeDefined();
        expect(factory.getBadgeEngine(GamificationStrategy.ELASTIC)).toBeDefined();
        expect(factory.getPointsEngine(GamificationStrategy.BASIC)).toBeDefined();
        expect(factory.getPointsEngine(GamificationStrategy.ELASTIC)).toBeDefined();
        expect(factory.getLeaderboardEngine(LeaderboardStrategy.POINTS_FIRST)).toBeDefined();
        expect(factory.getLeaderboardEngine(LeaderboardStrategy.BADGES_FIRST)).toBeDefined();
    });

    it('should throw error for unknown strategies', () => {
        expect(() => factory.getBadgeEngine('UNKNOWN' as any)).toThrow();
        expect(() => factory.getPointsEngine('UNKNOWN' as any)).toThrow();
        expect(() => factory.getLeaderboardEngine('UNKNOWN' as any)).toThrow();
    });
});
