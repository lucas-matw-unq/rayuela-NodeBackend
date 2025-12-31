import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { GamificationDao } from './gamification-dao.service';
import { GamificationTemplate } from './gamification.schema';
import { LeaderboardDao } from '../../leaderboard/persistence/leaderboard.dao';

describe('GamificationDao', () => {
  let dao: GamificationDao;
  let model: any;

  const mockModel = {
    findOne: jest.fn().mockReturnThis(),
    findOneAndUpdate: jest.fn().mockReturnThis(),
    create: jest.fn(),
    exec: jest.fn(),
  };

  const mockLeaderboardDao = {
    updateLeaderboardUsers: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GamificationDao,
        {
          provide: getModelToken(GamificationTemplate.collectionName()),
          useValue: mockModel,
        },
        { provide: LeaderboardDao, useValue: mockLeaderboardDao },
      ],
    }).compile();

    dao = module.get<GamificationDao>(GamificationDao);
    model = module.get(getModelToken(GamificationTemplate.collectionName()));
  });

  it('should be defined', () => {
    expect(dao).toBeDefined();
  });

  it('should add badge', async () => {
    const template = {
      badges: [],
      save: jest.fn().mockResolvedValue({}),
    };
    model.findOne.mockResolvedValue(template);
    await dao.addBadge('p1', { name: 'B1' } as any);
    expect(template.badges).toHaveLength(1);
  });

  it('should throw error if badge name exists', async () => {
    const template = {
      badges: [{ name: 'B1' }],
    };
    model.findOne.mockResolvedValue(template);
    await expect(dao.addBadge('p1', { name: 'B1' } as any)).rejects.toThrow(
      'Ya existe una insignia con ese nombre',
    );
  });

  it('should throw if project not found when adding badge', async () => {
    model.findOne.mockResolvedValue(null);
    await expect(dao.addBadge('p1', { name: 'B' } as any)).rejects.toThrow(
      'Project not found',
    );
  });

  it('should get point rules by project', async () => {
    model.findOne.mockReturnThis();
    model.exec.mockResolvedValue({ pointRules: [] });
    const res = await dao.getPointRulesByProject('p1');
    expect(res.pointRules).toEqual([]);
  });

  it('should find badge by id', async () => {
    model.findOne.mockReturnThis();
    model.exec.mockResolvedValue({ badges: [{ name: 'B1' }] });
    const res = await dao.findBadgeById('p1', 'b1');
    expect(res.badges).toHaveLength(1);
  });

  it('should update gamification', async () => {
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue({});
    await dao.updateGamification('p1', {} as any);
    expect(model.findOneAndUpdate).toHaveBeenCalled();
  });

  it('should add score rule', async () => {
    const template = { pointRules: [], save: jest.fn().mockResolvedValue({}) };
    model.findOne.mockResolvedValue(template);
    await dao.addScoreRule('p1', { score: 10 } as any);
    expect(template.pointRules).toHaveLength(1);
  });

  it('should update point rule', async () => {
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue({});
    await dao.updatePointRule('p1', { _id: 'r1' } as any);
    expect(model.findOneAndUpdate).toHaveBeenCalled();
  });

  it('should delete point rule', async () => {
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue({});
    await dao.deletePointRule('p1', 'r1');
    expect(model.findOneAndUpdate).toHaveBeenCalled();
  });

  it('should update badge', async () => {
    const template = {
      badges: [{ _id: 'b1', name: 'Old' }],
      save: jest.fn().mockResolvedValue({}),
    };
    model.findOne.mockResolvedValue(template);
    await dao.updateBadge('b1', { projectId: 'p1', name: 'New' } as any);
    expect(template.badges).toHaveLength(1);
    expect(template.badges[0].name).toBe('New');
  });

  it('should throw if project not found when updating badge', async () => {
    model.findOne.mockResolvedValue(null);
    await expect(
      dao.updateBadge('b1', { projectId: 'p1' } as any),
    ).rejects.toThrow('Project not found');
  });

  it('should get badges by project', async () => {
    model.findOne.mockReturnThis();
    model.exec.mockResolvedValue([]);
    const res = await dao.getBadgesByProject('p1');
    expect(res).toEqual([]);
  });

  it('should delete badge', async () => {
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue({});
    await dao.deleteBadge('p1', 'b1');
    expect(model.findOneAndUpdate).toHaveBeenCalled();
  });

  it('should get gamification by project id', async () => {
    const saved = {
      badges: [
        {
          _id: 'b1',
          projectId: 'p1',
          name: 'N',
          description: 'D',
          imageUrl: 'I',
          checkinsAmount: 1,
          mustContribute: false,
          previousBadges: [],
          taskType: 'T',
          areaId: 'A',
          timeIntervalId: 'TI',
        },
      ],
      pointRules: [
        {
          _id: 'r1',
          taskType: 'T',
          areaId: 'A',
          timeIntervalId: 'TI',
          score: 10,
          mustContribute: false,
        },
      ],
    };
    model.findOne.mockReturnThis();
    model.exec.mockResolvedValue(saved);
    const res = await dao.getGamificationByProjectId('p1');
    expect(res.projectId).toBe('p1');
    expect(res.badgesRules).toHaveLength(1);
    expect(res.pointRules).toHaveLength(1);
  });

  it('should throw if project not found when adding score rule', async () => {
    model.findOne.mockResolvedValue(null);
    await expect(dao.addScoreRule('p1', { score: 10 } as any)).rejects.toThrow(
      'Project not found',
    );
  });

  it('should create new gamification', async () => {
    model.create.mockResolvedValue({});
    await dao.createNewGamificationFor('p1');
    expect(model.create).toHaveBeenCalledWith({
      projectId: 'p1',
      badges: [],
      pointRules: [],
    });
  });

  it('should save move', async () => {
    const move = {
      checkin: { projectId: 'p1' },
      gameStatus: { newLeaderboard: [] },
    } as any;
    await dao.saveMove(move);
    expect(mockLeaderboardDao.updateLeaderboardUsers).toHaveBeenCalledWith(
      'p1',
      [],
    );
  });
});
