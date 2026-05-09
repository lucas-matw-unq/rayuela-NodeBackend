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
import { StorageService } from '../storage/storage.service';
import { CheckinIdempotencyDao } from './persistence/checkin-idempotency.dao';
import { ConflictException } from '@nestjs/common';

const mockCheckInDao = {
  create: jest.fn(),
  findAll: jest.fn(),
  findOne: jest.fn(),
  update: jest.fn(),
  remove: jest.fn(),
  findByProjectId: jest.fn(),
};

const mockIdempotencyDao = {
  claimKey: jest.fn(),
  setCheckinId: jest.fn(),
};

const mockStorageService = {
  uploadFile: jest.fn().mockResolvedValue('image-ref'),
};

const mockMoveDao = {
  create: jest.fn(),
};

const mockTaskService = {
  findByProjectId: jest.fn(),
  findOne: jest.fn(),
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
        { provide: StorageService, useValue: mockStorageService },
        {
          provide: GamificationEngineFactory,
          useValue: mockGamificationFactory,
        },
        { provide: CheckinIdempotencyDao, useValue: mockIdempotencyDao },
      ],
    }).compile();

    service = module.get<CheckinService>(CheckinService);
    jest.clearAllMocks();
    // Default: no key claimed yet → caller wins the race.
    mockIdempotencyDao.claimKey.mockResolvedValue(null);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    it('should create a checkin with multiple images, play the game, and save the results', async () => {
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

      const files = [
        {
          originalname: 'test1.jpg',
          buffer: Buffer.from('test1'),
          mimetype: 'image/jpeg',
        },
        {
          originalname: 'test2.jpg',
          buffer: Buffer.from('test2'),
          mimetype: 'image/jpeg',
        },
      ] as any[];

      mockStorageService.uploadFile
        .mockResolvedValueOnce('ref1')
        .mockResolvedValueOnce('ref2');

      const result = await service.create({ createCheckinDto, files });

      expect(mockTaskService.findByProjectId).toHaveBeenCalledWith('project1');
      expect(mockUserService.getByUserId).toHaveBeenCalledWith('user1');
      expect(mockProjectService.findOne).toHaveBeenCalledWith('project1');
      expect(mockCheckInDao.create).toHaveBeenCalled();
      expect(mockMoveDao.create).toHaveBeenCalled();
      expect(mockStorageService.uploadFile).toHaveBeenCalledTimes(2);
      expect(mockStorageService.uploadFile).toHaveBeenCalledWith(
        files[0],
        'checkins/user1',
      );
      expect(mockStorageService.uploadFile).toHaveBeenCalledWith(
        files[1],
        'checkins/user1',
      );

      expect(task.setSolved).toHaveBeenCalledWith(true);
      expect(user.addContribution).toHaveBeenCalledWith('task1');
      expect(mockTaskService.setTaskAsSolved).toHaveBeenCalledWith('task1');
      expect(mockUserService.update).toHaveBeenCalledWith('user1', user);
      expect(mockGamificationService.saveMove).toHaveBeenCalled();
      expect(result).toHaveProperty('id', 'checkin1');
      expect((result as any).contributesTo).toEqual({
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

      const result = await service.create({ createCheckinDto });

      expect(mockCheckInDao.create).toHaveBeenCalled();
      expect(mockMoveDao.create).toHaveBeenCalled();
      expect(task.setSolved).not.toHaveBeenCalled();
      expect(user.addContribution).not.toHaveBeenCalled();
      expect(mockTaskService.setTaskAsSolved).not.toHaveBeenCalled();
      expect(mockUserService.update).toHaveBeenCalledWith('user1', user);
      expect(mockGamificationService.saveMove).toHaveBeenCalled();
      expect(result).toHaveProperty('id', 'checkin1');
      expect((result as any).contributesTo).toBe(undefined);
    });

    it('should throw ConflictException if the project is not running', async () => {
      const data = {
        taskId: 'volunteering',
        projectId: 'project123',
        location: { latitude: '12', longitude: '34' },
      };

      const project = ProjectBuilder.withAvailable(false).build();
      ProjectBuilder.withAvailable(true);
      project.id = 'project123';
      project.name = 'Test Project';

      const task = TaskBuilder.withId('volunteering').build();

      const user = new User(
        'test@test.com',
        'testuser',
        'password',
        'Test User',
      );
      user.id = 'user1';
      user.addProject(project.id);

      mockTaskService.findByProjectId.mockResolvedValue([task]);
      mockUserService.getByUserId.mockResolvedValue(user);
      mockUserService.findAllByProjectId.mockResolvedValue([user]);
      mockProjectService.findOne.mockResolvedValue(project);
      mockCheckInDao.create.mockResolvedValue({ _id: 'checkin1' });

      const createPromise = service.create({ createCheckinDto: data as any });

      await expect(createPromise).rejects.toThrow(ConflictException);
      await expect(createPromise).rejects.toThrow('The project is not running');

      expect(mockCheckInDao.create).not.toHaveBeenCalled();
      expect(mockMoveDao.create).not.toHaveBeenCalled();
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

      await service.create({ createCheckinDto });

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

  describe('idempotency', () => {
    const dto: CreateCheckinDto = {
      datetime: new Date(),
      taskType: '',
      userId: 'user1',
      projectId: 'project1',
      latitude: '0',
      longitude: '0',
    };

    it('replays the original response when claimKey returns a completed hit', async () => {
      // claimKey returns a hit → key already processed for this user.
      mockIdempotencyDao.claimKey.mockResolvedValue({
        key: 'k-1',
        userId: 'user1',
        checkinId: 'old-checkin',
      });

      const relatedTask = TaskBuilder.withId('task-1')
        .withName('A task')
        .build();
      TaskBuilder.withId('default-task-id').withName('Default Task');

      mockCheckInDao.findOne.mockResolvedValue({
        id: 'old-checkin',
        latitude: '0',
        longitude: '0',
        date: new Date(),
        projectId: 'project1',
        taskType: '',
        contributesTo: 'task-1',
        imageRefs: ['ref-original'],
      });
      mockTaskService.findOne.mockResolvedValue(relatedTask);

      const result = await service.create({
        createCheckinDto: dto,
        idempotencyKey: 'k-1',
      });

      expect((result as any).contributesTo).toEqual({
        name: 'A task',
        id: 'task-1',
      });
      expect(mockTaskService.findOne).toHaveBeenCalledWith('task-1');

      // The replay path must NOT touch the create pipeline.
      expect(mockTaskService.findByProjectId).not.toHaveBeenCalled();
      expect(mockCheckInDao.create).not.toHaveBeenCalled();
      expect(mockMoveDao.create).not.toHaveBeenCalled();
      expect(mockIdempotencyDao.setCheckinId).not.toHaveBeenCalled();

      expect((result as any).replayed).toBe(true);
      expect(result.id).toBe('old-checkin');
      expect((result as any)._checkin.imageRefs).toEqual(['ref-original']);
      // Empty gameStatus on replay so the client can't double-count.
      expect((result as any)._gameStatus.newPoints).toBe(0);
      expect((result as any)._gameStatus.newBadges).toEqual([]);
    });

    it('throws ConflictException when the key was minted by another user', async () => {
      // claimKey itself throws when userId does not match.
      mockIdempotencyDao.claimKey.mockRejectedValue(
        new ConflictException(
          'Idempotency-Key already used by another account',
        ),
      );

      await expect(
        service.create({ createCheckinDto: dto, idempotencyKey: 'k-1' }),
      ).rejects.toBeInstanceOf(ConflictException);

      expect(mockCheckInDao.create).not.toHaveBeenCalled();
    });

    it('throws ConflictException when key is claimed but checkin is still in-flight', async () => {
      // claimKey returns a hit with no checkinId → another request is processing.
      mockIdempotencyDao.claimKey.mockResolvedValue({
        key: 'k-pending',
        userId: 'user1',
        checkinId: undefined,
      });

      await expect(
        service.create({ createCheckinDto: dto, idempotencyKey: 'k-pending' }),
      ).rejects.toThrow(
        'Idempotency-Key is already being processed, retry shortly',
      );

      expect(mockCheckInDao.create).not.toHaveBeenCalled();
    });

    it('calls setCheckinId after a successful first-time create', async () => {
      // claimKey returns null → this request won the race.
      mockIdempotencyDao.claimKey.mockResolvedValue(null);

      const user = new User('a@b', 'u', 'p', 'U');
      user.id = 'user1';
      user.addBadgeFromProject = jest.fn();
      user.addContribution = jest.fn();

      const task = TaskBuilder.build();
      jest.spyOn(task, 'contributesToCheckin').mockReturnValue(false);
      jest.spyOn(task, 'setSolved');

      const project = ProjectBuilder.build();
      user.addProject(project.id);

      mockTaskService.findByProjectId.mockResolvedValue([task]);
      mockUserService.getByUserId.mockResolvedValue(user);
      mockUserService.findAllByProjectId.mockResolvedValue([user]);
      mockProjectService.findOne.mockResolvedValue(project);
      mockCheckInDao.create.mockResolvedValue({ _id: 'fresh-checkin' });

      await service.create({
        createCheckinDto: dto,
        idempotencyKey: 'k-new',
      });

      expect(mockIdempotencyDao.setCheckinId).toHaveBeenCalledWith(
        'k-new',
        'fresh-checkin',
      );
    });
  });
});
