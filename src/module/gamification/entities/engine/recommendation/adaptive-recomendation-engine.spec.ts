import { Test, TestingModule } from '@nestjs/testing';
import { AdaptiveRecommendationEngine } from './adaptive-recommendation-engine';
import { Task } from '../../../../task/entities/task.entity';
import { TimeInterval } from '../../../../task/entities/time-restriction.entity';
import { ConfigModule } from '@nestjs/config';
import * as process from 'node:process';
import { User } from '../../../../auth/users/user.entity';

// Testear el arranque en frio, cuando al persona no completo tareas con un resultado aleatorio
// Ir completando tareas y verificar que se recomiende lo indicado

describe('AdaptiveRecommendationEngine', () => {
  let recommendationEngine: AdaptiveRecommendationEngine;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
      ],
      providers: [AdaptiveRecommendationEngine],
    }).compile();

    recommendationEngine = module.get<AdaptiveRecommendationEngine>(
      AdaptiveRecommendationEngine,
    );
  });

  it('should be defined', () => {
    expect(recommendationEngine).toBeDefined();
  });

  it('should use default values if env vars are missing', () => {
    const originalK = process.env.K;
    const originalNeutral = process.env.NEUTRAL_SCORE;
    const originalLimit = process.env.RECOMMENDATIONS_LIMIT;
    const originalMaxStars = process.env.MAX_STARS_AMOUNT;

    delete process.env.K;
    delete process.env.NEUTRAL_SCORE;
    delete process.env.RECOMMENDATIONS_LIMIT;
    delete process.env.MAX_STARS_AMOUNT;

    const engine = new AdaptiveRecommendationEngine();
    expect(engine['k']).toBe(5);
    expect(engine['NEUTRAL_SCORE']).toBe(4);
    expect(engine['RECOMMENDATIONS_LIMIT']).toBe(10);
    expect(engine['MAX_STARS_AMOUNT']).toBe(5);

    if (originalK) process.env.K = originalK;
    if (originalNeutral) process.env.NEUTRAL_SCORE = originalNeutral;
    if (originalLimit) process.env.RECOMMENDATIONS_LIMIT = originalLimit;
    if (originalMaxStars) process.env.MAX_STARS_AMOUNT = originalMaxStars;
  });

  /*
   * Task similarity tests
   */

  describe('calculateTaskSimilarity', () => {
    it('should return 1 for identical tasks', () => {
      const task = createTask('task1', 'area1', 'morning', 'type1');
      expect(recommendationEngine['calculateTaskSimilarity'](task, task)).toBe(
        1,
      );
    });

    it('should return 0 for completely different tasks', () => {
      const task = createTask('task1', 'area1', 'morning', 'type1');
      const task2 = createTask('task2', 'area2', 'afternoon', 'type2');
      expect(recommendationEngine['calculateTaskSimilarity'](task, task2)).toBe(
        0,
      );
    });

    it('should return a similarity score between 0 and 1', () => {
      const task1 = createTask('task1', 'area1', 'morning', 'type1');
      const task2 = createTask('task2', 'area1', 'afternoon', 'type2');
      const similarity = recommendationEngine['calculateTaskSimilarity'](
        task1,
        task2,
      );
      expect(similarity).toBeGreaterThan(0.33);
      expect(similarity).toBeLessThan(0.34);
    });
  });

  /*
   * getMostSimilarTasks tests
   */

  describe('getMostSimilarTasks', () => {
    it('should return K tasks', () => {
      const targetTask = createTask('target', 'area1', 'morning', 'type1');
      const allTasks = [
        createTask('task1', 'area1', 'morning', 'type1'),
        createTask('task2', 'area2', 'afternoon', 'type2'),
        createTask('task3', 'area1', 'evening', 'type1'),
        createTask('task4', 'area1', 'evening', 'type5'),
      ];
      const similarTasks = recommendationEngine['getMostSimilarTasks'](
        targetTask,
        allTasks,
      );
      expect(similarTasks.length).toBeLessThanOrEqual(Number(process.env.K));
    });
  });

  /*
   * estimateTaskRating tests
   */
  describe('estimateTaskRating', () => {
    it('should return 0 if no similar tasks have ratings', () => {
      const estimatedRating = recommendationEngine['estimateTaskRating'](
        [],
        {},
      );
      expect(estimatedRating).toBe(0);
    });

    it('should return a weighted average rating', () => {
      const similarTasks = [
        {
          task: createTask('task2', 'area1', 'morning', 'type1'),
          similarity: 0.8,
        },
        {
          task: createTask('task3', 'area1', 'morning', 'type1'),
          similarity: 0.6,
        },
      ];
      const ratings = { task2: 5, task3: 3 };
      const estimatedRating = recommendationEngine['estimateTaskRating'](
        similarTasks,
        ratings,
      );
      expect(estimatedRating).toBeGreaterThan(0.828571);
      expect(estimatedRating).toBeLessThan(0.828572);
    });

    it('should return a value between 0 and 1', () => {
      const similarTasks = [
        {
          task: createTask('task4', 'area3', 'morning', 'type4'),
          similarity: 0.7,
        },
        {
          task: createTask('task5', 'area3', 'morning', 'type4'),
          similarity: 0.5,
        },
      ];
      const ratings = { task4: 2, task5: 4 };
      const estimatedRating = recommendationEngine['estimateTaskRating'](
        similarTasks,
        ratings,
      );

      expect(estimatedRating).toBeGreaterThanOrEqual(0);
      expect(estimatedRating).toBeLessThanOrEqual(1);
    });

    it('should use neutral score if rating is missing for a similar task', () => {
      const similarTasks = [{ task: createTask('task1', 'a', 'm', 't'), similarity: 1 }];
      const estimatedRating = recommendationEngine['estimateTaskRating'](similarTasks, {});
      expect(estimatedRating).toBe(0.8);
    });
  });

  /*
   * generateRecommendations tests
   */
  describe('generateRecommendations', () => {
    const user = {
      contributions: ['task1', 'task2'], // IDs de tareas completadas
    } as unknown as User;

    it('should return an empty list if no tasks are available', () => {
      const recommendations = recommendationEngine.generateRecommendations(
        user,
        {},
        [],
      );
      expect(recommendations).toEqual([]);
    });

    it('should generate ordered task recommendations', () => {
      const completedTasksRatings = { task1: 5, task2: 3 };
      const allTasks = [
        createTask('task1', 'area1', 'morning', 'type1'),
        createTask('task3', 'area2', 'afternoon', 'type2'),
      ];
      const recommendations = recommendationEngine.generateRecommendations(
        user,
        completedTasksRatings,
        allTasks,
      );
      expect(recommendations.length).toBeGreaterThan(0);
      expect(recommendations[0].estimatedRating).toBeGreaterThanOrEqual(
        recommendations[1]?.estimatedRating ?? 0,
      );
      recommendations.forEach((rec) => {
        expect(rec.estimatedRating).toBeGreaterThanOrEqual(0);
        expect(rec.estimatedRating).toBeLessThanOrEqual(1);
      });
    });

    /*
     * cold start tests
     */
    it('should handle cold start by assigning default or random ratings', () => {
      const coldUser = {
        contributions: [],
      } as unknown as User;

      const allTasks = [
        createTask('task1', 'area1', 'morning', 'type1'),
        createTask('task2', 'area2', 'afternoon', 'type2'),
        createTask('task3', 'area1', 'evening', 'type1'),
      ];

      const recommendations = recommendationEngine.generateRecommendations(
        coldUser,
        {},
        allTasks,
      );

      expect(recommendations.length).toBeGreaterThan(0);
      recommendations.forEach((rec) => {
        expect(rec.estimatedRating).toBeGreaterThanOrEqual(0);
        expect(rec.estimatedRating).toBeLessThanOrEqual(1);
      });
    });

    it('should improve recommendations as more tasks are completed', () => {
      const progressingUser = {
        contributions: ['task1'],
      } as unknown as User;

      const completedTasksRatings = { task1: 5 };
      const allTasks = [
        createTask('task1', 'area1', 'morning', 'type1'),
        createTask('task2', 'area1', 'morning', 'type1'),
        createTask('task3', 'area2', 'evening', 'type3'),
      ];

      const recommendations = recommendationEngine.generateRecommendations(
        progressingUser,
        completedTasksRatings,
        allTasks,
      );

      expect(recommendations.length).toBeGreaterThan(0);
      const ratedTask = recommendations.find((r) => r.task.getId() === 'task2');
      expect(ratedTask?.estimatedRating).toBeGreaterThan(0.5);

      recommendations.forEach((rec) => {
        expect(rec.estimatedRating).toBeGreaterThanOrEqual(0);
        expect(rec.estimatedRating).toBeLessThanOrEqual(1);
      });
    });
  });
});

function createTask(
  id: string,
  areaId: string,
  timeName: string,
  type: string,
): Task {
  return new Task(
    id,
    `Task ${id}`,
    `Description for ${id}`,
    'project1',
    new TimeInterval(
      timeName,
      [1, 2, 3, 4, 5],
      {
        start: '06:00:00',
        end: '12:00:00',
      },
      new Date('2024-01-01'),
      new Date('2024-12-31'),
    ),
    {
      type: 'Feature',
      properties: { id: areaId },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [0, 0],
            [1, 1],
            [1, 0],
            [0, 0],
          ],
        ],
      },
    },
    type,
  );
}
