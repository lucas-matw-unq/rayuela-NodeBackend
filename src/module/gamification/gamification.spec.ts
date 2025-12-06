import { Test, TestingModule } from '@nestjs/testing';
import { GamificationService } from './gamification.service';
import { GamificationDao } from './persistence/gamification-dao.service';
import { CreateBadgeRuleDTO } from './dto/create-badge-rule-d-t.o';
import { UpdateGamificationDto } from './dto/update-gamification.dto';
import { UpdateBadgeRuleDTO } from './dto/update-badge-rule-d-t.o';
import { CreateScoreRuleDto } from './dto/create-score-rule-dto';
import { UpdateScoreRuleDto } from './dto/update-score-rule.dto';
import { Move } from '../checkin/entities/move.entity';

const mockGamificationDao = {
  addBadge: jest.fn(),
  getGamificationByProjectId: jest.fn(),
  updateGamification: jest.fn(),
  deleteBadge: jest.fn(),
  updateBadge: jest.fn(),
  addScoreRule: jest.fn(),
  updatePointRule: jest.fn(),
  deletePointRule: jest.fn(),
  saveMove: jest.fn(),
};

describe('GamificationService', () => {
  let service: GamificationService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GamificationService,
        {
          provide: GamificationDao,
          useValue: mockGamificationDao,
        },
      ],
    }).compile();

    service = module.get<GamificationService>(GamificationService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createBadge', () => {
    it('should call gamificationDao.addBadge with correct parameters', async () => {
      const dto: CreateBadgeRuleDTO = {
        _id: '',
        areaId: '',
        checkinsAmount: 0,
        description: '',
        imageUrl: '',
        mustContribute: false,
        name: '',
        previousBadges: [],
        projectId: '',
        taskType: '',
        timeIntervalId: '',
      };
      mockGamificationDao.addBadge.mockResolvedValue(dto);
      await service.createBadge(dto);
      expect(mockGamificationDao.addBadge).toHaveBeenCalledWith(
        dto.projectId,
        dto,
      );
    });
  });

  describe('findByProjectId', () => {
    it('should call gamificationDao.getGamificationByProjectId', async () => {
      const projectId = 'p1';
      mockGamificationDao.getGamificationByProjectId.mockResolvedValue({});
      await service.findByProjectId(projectId);
      expect(
        mockGamificationDao.getGamificationByProjectId,
      ).toHaveBeenCalledWith(projectId);
    });
  });

  describe('update', () => {
    it('should call gamificationDao.updateGamification', async () => {
      const projectId = 'p1';
      const dto: UpdateGamificationDto = {
        badgesRules: [],
        pointRules: [],
        projectId: '',
      };
      mockGamificationDao.updateGamification.mockResolvedValue({});
      await service.update(projectId, dto);
      expect(mockGamificationDao.updateGamification).toHaveBeenCalledWith(
        projectId,
        dto,
      );
    });
  });

  describe('removeBadge', () => {
    it('should call gamificationDao.deleteBadge', async () => {
      const projectId = 'p1';
      const badgeId = 'b1';
      mockGamificationDao.deleteBadge.mockResolvedValue({});
      await service.removeBadge(projectId, badgeId);
      expect(mockGamificationDao.deleteBadge).toHaveBeenCalledWith(
        projectId,
        badgeId,
      );
    });
  });

  describe('updateBadge', () => {
    it('should call gamificationDao.updateBadge', async () => {
      const badgeId = 'b1';
      const dto: UpdateBadgeRuleDTO = {};
      mockGamificationDao.updateBadge.mockResolvedValue({});
      await service.updateBadge(badgeId, dto);
      expect(mockGamificationDao.updateBadge).toHaveBeenCalledWith(
        badgeId,
        dto,
      );
    });
  });

  describe('createScoreRule', () => {
    it('should call gamificationDao.addScoreRule', async () => {
      const dto: CreateScoreRuleDto = {
        _id: '',
        areaId: '',
        mustContribute: false,
        projectId: '',
        score: 0,
        taskType: '',
        timeIntervalId: '',
      };
      mockGamificationDao.addScoreRule.mockResolvedValue({});
      await service.createScoreRule(dto);
      expect(mockGamificationDao.addScoreRule).toHaveBeenCalledWith(
        dto.projectId,
        dto,
      );
    });
  });

  describe('updateScoreRule', () => {
    it('should call gamificationDao.updatePointRule', async () => {
      const dto: UpdateScoreRuleDto = {
        projectId: 'p1',
      };
      mockGamificationDao.updatePointRule.mockResolvedValue({});
      await service.updateScoreRule(dto);
      expect(mockGamificationDao.updatePointRule).toHaveBeenCalledWith(
        dto.projectId,
        dto,
      );
    });
  });

  describe('removeScoreRule', () => {
    it('should call gamificationDao.deletePointRule', async () => {
      const projectId = 'p1';
      const ruleId = 's1';
      mockGamificationDao.deletePointRule.mockResolvedValue({});
      await service.removeScoreRule(projectId, ruleId);
      expect(mockGamificationDao.deletePointRule).toHaveBeenCalledWith(
        projectId,
        ruleId,
      );
    });
  });

  describe('saveMove', () => {
    it('should call gamificationDao.saveMove', async () => {
      const move = {} as Move;
      mockGamificationDao.saveMove.mockResolvedValue({});
      await service.saveMove(move);
      expect(mockGamificationDao.saveMove).toHaveBeenCalledWith(move);
    });
  });
});
