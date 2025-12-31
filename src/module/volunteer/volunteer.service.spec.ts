import { Test, TestingModule } from '@nestjs/testing';
import { VolunteerService } from './volunteer.service';
import { UserService } from '../auth/users/user.service';
import { ProjectService } from '../project/project.service';
import { User } from '../auth/users/user.entity';
import { UserRole } from '../auth/users/user.schema';

describe('VolunteerService', () => {
  let service: VolunteerService;

  const mockUserService = {
    getByUserId: jest.fn(),
    update: jest.fn(),
  };

  const mockProjectService = {
    findAll: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        VolunteerService,
        { provide: UserService, useValue: mockUserService },
        { provide: ProjectService, useValue: mockProjectService },
      ],
    }).compile();

    service = module.get<VolunteerService>(VolunteerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('subscribeToProject', () => {
    it('should subscribe if not already subscribed', async () => {
      const userJwt = {
        userId: 'user1',
        username: 'test',
        role: UserRole.Volunteer,
      };
      const user = new User(
        'Test',
        'test',
        'test@test.com',
        'pass',
        '',
        false,
        UserRole.Volunteer,
      );
      user.isSubscribedToProject = jest.fn().mockReturnValue(false);
      user.subscribeToProject = jest.fn();

      mockUserService.getByUserId.mockResolvedValue(user);
      mockUserService.update.mockResolvedValue(user);

      await service.subscribeToProject(userJwt, 'proj1');

      expect(user.subscribeToProject).toHaveBeenCalledWith('proj1');
      expect(mockUserService.update).toHaveBeenCalledWith('user1', user);
    });

    it('should unsubscribe if already subscribed', async () => {
      const userJwt = {
        userId: 'user1',
        username: 'test',
        role: UserRole.Volunteer,
      };
      const user = new User(
        'Test',
        'test',
        'test@test.com',
        'pass',
        '',
        false,
        UserRole.Volunteer,
      );
      user.isSubscribedToProject = jest.fn().mockReturnValue(true);
      user.unsubscribeFromProject = jest.fn();

      mockUserService.getByUserId.mockResolvedValue(user);
      mockUserService.update.mockResolvedValue(user);

      await service.subscribeToProject(userJwt, 'proj1');

      expect(user.unsubscribeFromProject).toHaveBeenCalledWith('proj1');
      expect(mockUserService.update).toHaveBeenCalledWith('user1', user);
    });
  });

  describe('findProjects', () => {
    it('should return projects with subscription status sorted', async () => {
      const userId = 'user1';
      const user = {
        gameProfiles: [{ projectId: 'proj1', active: true }],
      } as any;
      const projects = [
        { _id: 'proj1', name: 'Project 1' },
        { _id: 'proj2', name: 'Project 2' },
      ] as any;

      mockUserService.getByUserId.mockResolvedValue(user);
      mockProjectService.findAll.mockResolvedValue(projects);

      const result = await service.findProjects(userId);

      expect(result).toHaveLength(2);
      expect(result[0]._id).toBe('proj1');
      expect(result[0].subscribed).toBe(true);
      expect(result[1]._id).toBe('proj2');
      expect(result[1].subscribed).toBe(false);
    });

    it('should handle sorting logic comprehensively', async () => {
      const p1 = { subscribed: true };
      const p2 = { subscribed: false };
      const p3 = { subscribed: true };
      const p4 = { subscribed: false };

      const sorted = (service as any).sortSubscriptions([p2, p1]);
      expect(sorted[0].subscribed).toBe(true);
      expect(sorted[1].subscribed).toBe(false);

      const equalTrue = (service as any).sortSubscriptions([p1, p3]);
      expect(equalTrue).toEqual([p1, p3]);

      const equalFalse = (service as any).sortSubscriptions([p2, p4]);
      expect(equalFalse).toEqual([p2, p4]);
    });
  });

  describe('findPublicProjects', () => {
    it('should call projectService.findAll', async () => {
      mockProjectService.findAll.mockResolvedValue([]);
      await service.findPublicProjects();
      expect(mockProjectService.findAll).toHaveBeenCalled();
    });
  });
});
