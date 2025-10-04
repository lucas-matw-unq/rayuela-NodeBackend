import { ElasticPointsEngine } from './elastic-points-engine';
import { Checkin } from '../../../../checkin/entities/checkin.entity';
import {
  GamificationStrategy,
  RecommendationStrategy,
} from '../../../../project/dto/create-project.dto';
import { BasicPointsEngine } from './basic-points-engine';
import { User } from '../../../../auth/users/user.entity';
import { Project } from '../../../../project/entities/project';
import { BasicBadgeEngine } from './basic-badge-engine';
import { BasicLeaderbardEngine } from './basic-leaderboard-engine';
import { Game } from '../../../../checkin/entities/game.entity';

jest.mock('./basic-points-engine');

describe('ElasticPointsEngine', () => {
  let engine: ElasticPointsEngine;
  let mockCheckin: Checkin;
  let mockGame: Game;
  let mockProject: Project;
  let user: User;
  let user2: User;
  let user3: User;
  let basePoints: number;

  beforeEach(() => {
    engine = new ElasticPointsEngine();
    basePoints = 10;
    jest
      .spyOn(BasicPointsEngine.prototype, 'reward')
      .mockReturnValue(basePoints);

    user = new User('TestName', 'Test username', 'test@test.com', 'pw');
    user2 = new User('TestName2', 'Test username2', 'test@test.com2', 'pw2');
    user3 = new User('TestName3', 'Test username3', 'test@test.com3', 'pw3');

    user.addProject('test');
    user2.addProject('test');
    user3.addProject('test');

    mockCheckin = new Checkin(
      '-55.00',
      '55.00',
      new Date(),
      'test',
      user,
      'test',
      'test',
    );

    mockProject = new Project(
      'test',
      'test',
      'testdescription',
      'testImage',
      'testweb',
      true,
      null,
      [],
      [],
      'user1',
      null,
      GamificationStrategy.ELASTIC,
      RecommendationStrategy.SIMPLE,
    );

    mockGame = new Game(
      mockProject,
      new ElasticPointsEngine(),
      new BasicBadgeEngine(),
      new BasicLeaderbardEngine(),
      [],
      [user, user2, user3],
    );
  });

  describe('reward', () => {
    it('should return base points when there are no contributions', () => {
      const result = engine.reward(mockCheckin, mockGame);
      expect(result).toBe(basePoints);
    });

    it('should correctly apply the weighting factor when there are contributions', () => {
      user2.addContribution('1');
      user2.addContribution('2');

      user3.addContribution('1');

      user2.addPointsFromProject(basePoints * 2, 'test');
      user3.addPointsFromProject(basePoints, 'test');

      mockGame.users = [user2, user3];
      mockCheckin.user = user3;

      const result = engine.reward(mockCheckin, mockGame);
      expect(result).toBeGreaterThan(basePoints);
    });

    it('should return base points when maxPoints is 0', () => {
      mockGame.users = [user];

      const result = engine.reward(mockCheckin, mockGame);
      expect(result).toBe(basePoints);
    });
  });

  describe('assignableTo', () => {
    it('should return true if project has ELASTIC gamification strategy', () => {
      expect(engine.assignableTo(mockProject as Project)).toBe(true);
    });

    it('should return false if project does not have ELASTIC gamification strategy', () => {
      mockProject.gamificationStrategy = GamificationStrategy.BASIC;
      expect(engine.assignableTo(mockProject as Project)).toBe(false);
    });
  });
});
