import { Test, TestingModule } from '@nestjs/testing';
import { LeaderboardService } from './leaderboard.service';
import { LeaderboardDao } from './persistence/leaderboard.dao';

describe('LeaderboardService', () => {
    let service: LeaderboardService;
    let dao: LeaderboardDao;

    const mockLeaderboardDao = {
        findByProjectId: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                LeaderboardService,
                { provide: LeaderboardDao, useValue: mockLeaderboardDao },
            ],
        }).compile();

        service = module.get<LeaderboardService>(LeaderboardService);
        dao = module.get<LeaderboardDao>(LeaderboardDao);
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    it('should call dao.findByProjectId', async () => {
        mockLeaderboardDao.findByProjectId.mockResolvedValue({} as any);
        await service.getLeaderboardFor('p1');
        expect(dao.findByProjectId).toHaveBeenCalledWith('p1');
    });
});
