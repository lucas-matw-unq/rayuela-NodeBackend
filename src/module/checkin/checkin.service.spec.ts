import { Test, TestingModule } from '@nestjs/testing';
import { CheckinService } from './checkin.service';
import { CheckInDao } from './persistence/checkin.dao';
import { TaskService } from '../task/task.service';
import { UserService } from '../auth/users/user.service';
import { ProjectService } from '../project/project.service';
import { MoveDao } from './persistence/move.dao';
import { GamificationService } from '../gamification/gamification.service';
import { GamificationEngineFactory } from '../gamification/entities/engine/gamification/gamification-strategy-factory';
import { CreateCheckinDto } from './dto/create-checkin.dto';
import { User } from '../auth/users/user.entity';
import { UpdateCheckinDto } from './dto/update-checkin.dto';
import ProjectBuilder from '../project/project.builder';
import TaskBuilder from '../task/task.builder';
import CheckinBuilder from './checkin.builder';

const mockCheckInDao = {
  create: jest.fn(),
  findAll: jest.fn(),
  findOne: jest.fn(),
  update: jest.fn(),
  remove: jest.fn(),
  findByProjectId: jest.fn(),
};

const mockMoveDao = {
  create: jest.fn(),
};

const mockTaskService = {
  findByProjectId: jest.fn(),
  setTaskAsSolved: jest.fn(),
};

const mockUserService = {
  getByUserId: jest.fn(),
  findAllByProjectId: jest.fn(),
  update: jest.fn(),
  rate: jest.fn(),
};

const mockProjectService = {
  findOne: jest.fn(),
};

const mockGamificationService = {
  saveMove: jest.fn(),
};

const mockGamificationFactory = {
  getBadgeEngine: jest.fn(() => ({
    newBadgesFor: jest.fn(() => []),
  })),
  getPointsEngine: jest.fn(() => ({
    reward: jest.fn(() => 0),
  })),
  getLeaderboardEngine: jest.fn(() => ({
    build: jest.fn(() => ({ leaderboard: [] })),
  })),
};

describe('CheckinService', () => {
  let service: CheckinService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CheckinService,
        { provide: CheckInDao, useValue: mockCheckInDao },
        { provide: MoveDao, useValue: mockMoveDao },
        { provide: TaskService, useValue: mockTaskService },
        { provide: UserService, useValue: mockUserService },
        { provide: ProjectService, useValue: mockProjectService },
        { provide: GamificationService, useValue: mockGamificationService },
        {
          provide: GamificationEngineFactory,
          useValue: mockGamificationFactory,
        },
      ],
    }).compile();

    service = module.get<CheckinService>(CheckinService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a checkin, play the game, and save the results', async () => {
      const createCheckinDto: CreateCheckinDto = {
        datetime: new Date(),
        taskType: '',
        userId: 'user1',
        projectId: 'project1',
        latitude: '0',
        longitude: '0',
      };

      const user = new User(
        'test@test.com',
        'testuser',
        'password',
        'Test User',
      );
      user.id = 'user1';
      user.addBadgeFromProject = jest.fn();
      user.addContribution = jest.fn();

      const task = TaskBuilder.withId('task1').withName('Test Task').build();
      jest.spyOn(task, 'contributesToCheckin').mockReturnValue(true);
      jest.spyOn(task, 'setSolved');

      const project = ProjectBuilder.build();
      user.addProject(project.id);

      mockTaskService.findByProjectId.mockResolvedValue([task]);
      mockUserService.getByUserId.mockResolvedValue(user);
      mockUserService.findAllByProjectId.mockResolvedValue([user]);
      mockProjectService.findOne.mockResolvedValue(project);
      mockCheckInDao.create.mockResolvedValue({ _id: 'checkin1' });

      const result = await service.create(createCheckinDto);

      expect(mockTaskService.findByProjectId).toHaveBeenCalledWith('project1');
      expect(mockUserService.getByUserId).toHaveBeenCalledWith('user1');
      expect(mockProjectService.findOne).toHaveBeenCalledWith('project1');
      expect(mockCheckInDao.create).toHaveBeenCalled();
      expect(mockMoveDao.create).toHaveBeenCalled();
      expect(task.setSolved).toHaveBeenCalledWith(true);
      expect(user.addContribution).toHaveBeenCalledWith('task1');
      expect(mockTaskService.setTaskAsSolved).toHaveBeenCalledWith('task1');
      expect(mockUserService.update).toHaveBeenCalledWith('user1', user);
      expect(mockGamificationService.saveMove).toHaveBeenCalled();
      expect(result).toHaveProperty('id', 'checkin1');
      expect(result.contributesTo).toEqual({
        name: 'Test Task',
        id: 'task1',
      });
    });

    it('should create a checkin without a contribution', async () => {
      const createCheckinDto: CreateCheckinDto = {
        datetime: new Date(),
        taskType: 'type',
        userId: 'user1',
        projectId: 'project1',
        latitude: '0',
        longitude: '0',
      };

      const user = new User(
        'test@test.com',
        'testuser',
        'password',
        'Test User',
      );
      user.id = 'user1';
      user.addBadgeFromProject = jest.fn();
      user.addContribution = jest.fn();

      const task = TaskBuilder.build();
      jest.spyOn(task, 'contributesToCheckin').mockReturnValue(false); // No contribution
      jest.spyOn(task, 'setSolved');

      const project = ProjectBuilder.build();
      user.addProject(project.id);

      mockTaskService.findByProjectId.mockResolvedValue([task]);
      mockUserService.getByUserId.mockResolvedValue(user);
      mockUserService.findAllByProjectId.mockResolvedValue([user]);
      mockProjectService.findOne.mockResolvedValue(project);
      mockCheckInDao.create.mockResolvedValue({ _id: 'checkin1' });

      const result = await service.create(createCheckinDto);

      expect(mockCheckInDao.create).toHaveBeenCalled();
      expect(mockMoveDao.create).toHaveBeenCalled();
      expect(task.setSolved).not.toHaveBeenCalled();
      expect(user.addContribution).not.toHaveBeenCalled();
      expect(mockTaskService.setTaskAsSolved).not.toHaveBeenCalled();
      expect(mockUserService.update).toHaveBeenCalledWith('user1', user);
      expect(mockGamificationService.saveMove).toHaveBeenCalled();
      expect(result).toHaveProperty('id', 'checkin1');
      expect(result.contributesTo).toBe(undefined);
    });

    it('should add badges to user if game results in new badges', async () => {
      const createCheckinDto: CreateCheckinDto = {
        datetime: new Date(),
        taskType: 'type',
        userId: 'user1',
        projectId: 'project1',
        latitude: '0',
        longitude: '0',
      };

      const project = ProjectBuilder.build();
      const task = TaskBuilder.build();
      const user = new User('t@t.com', 'u', 'p', 'T');
      user.id = 'user1';
      user.addBadgeFromProject = jest.fn();
      user.addProject(project.id); // Ensure game profile exists

      mockTaskService.findByProjectId.mockResolvedValue([task]);
      mockUserService.getByUserId.mockResolvedValue(user);
      mockUserService.findAllByProjectId.mockResolvedValue([user]);
      mockProjectService.findOne.mockResolvedValue(project);
      mockCheckInDao.create.mockResolvedValue({ _id: 'checkin1' });

      // Mock badge engine to return a new badge
      mockGamificationFactory.getBadgeEngine.mockReturnValue({
        newBadgesFor: jest.fn().mockReturnValue([{ name: 'New Badge' }]),
      });

      await service.create(createCheckinDto);

      expect(user.addBadgeFromProject).toHaveBeenCalledWith(
        ['New Badge'],
        'project1',
      );

      // Reset mock for other tests
      mockGamificationFactory.getBadgeEngine.mockReturnValue({
        newBadgesFor: jest.fn().mockReturnValue([]),
      });
    });
  });

  describe('findAll', () => {
    it('should return all checkins', async () => {
      const checkins = [CheckinBuilder.build()];
      mockCheckInDao.findAll.mockResolvedValue(checkins);
      expect(await service.findAll()).toBe(checkins);
      expect(mockCheckInDao.findAll).toHaveBeenCalled();
    });
  });

  describe('findOne', () => {
    it('should return a single checkin', async () => {
      const checkin = CheckinBuilder.build();
      mockCheckInDao.findOne.mockResolvedValue(checkin);
      expect(await service.findOne('1')).toBe(checkin);
      expect(mockCheckInDao.findOne).toHaveBeenCalledWith('1');
    });
  });

  describe('update', () => {
    it('should update a checkin', async () => {
      const updateDto: UpdateCheckinDto = {};
      const result = { id: '1' };
      mockCheckInDao.update.mockResolvedValue(result);
      expect(await service.update('1', updateDto)).toBe(result);
      expect(mockCheckInDao.update).toHaveBeenCalledWith('1', updateDto);
    });
  });

  describe('remove', () => {
    it('should remove a checkin', async () => {
      const result = { id: '1' };
      mockCheckInDao.remove.mockResolvedValue(result);
      expect(await service.remove('1')).toBe(result);
      expect(mockCheckInDao.remove).toHaveBeenCalledWith('1');
    });
  });

  describe('findByProjectId', () => {
    it('should find checkins by project id', async () => {
      const checkins = [CheckinBuilder.build()];
      mockCheckInDao.findByProjectId.mockResolvedValue(checkins);
      expect(await service.findByProjectId('user1', 'project1')).toBe(checkins);
      expect(mockCheckInDao.findByProjectId).toHaveBeenCalledWith(
        'user1',
        'project1',
      );
    });
  });

  describe('rate', () => {
    it('should rate a checkin', async () => {
      const params = { checkinId: 'c1', rate: 5, userId: 'u1' };
      const checkin = CheckinBuilder.build();
      mockCheckInDao.findOne.mockResolvedValue(checkin);
      mockUserService.rate.mockResolvedValue({ success: true });

      const result = await service.rate(params);

      expect(mockCheckInDao.findOne).toHaveBeenCalledWith(params.checkinId);
      expect(mockUserService.rate).toHaveBeenCalledWith(
        params.userId,
        checkin,
        params.rate,
      );
      expect(result).toEqual({ success: true });
    });
  });
});
