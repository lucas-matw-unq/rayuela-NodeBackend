import { ProjectMapper } from './ProjectMapper';
import { Project } from './project';
import {
  GamificationStrategy,
  LeaderboardStrategy,
  RecommendationStrategy,
} from '../dto/create-project.dto';

describe('ProjectMapper', () => {
  const template = {
    _id: '1',
    name: 'p1',
    description: 'desc',
    image: 'img',
    web: 'web',
    available: true,
    areas: { type: 'FeatureCollection', features: [] },
    taskTypes: [],
    timeIntervals: [],
    ownerId: 'o1',
    gamificationStrategy: GamificationStrategy.BASIC,
    leaderboardStrategy: LeaderboardStrategy.POINTS_FIRST,
    recommendationStrategy: RecommendationStrategy.SIMPLE,
    manualLocation: false,
  } as any;

  it('should map template to entity', () => {
    const entity = ProjectMapper.toEntity(template);
    expect(entity.id).toBe('1');
    expect(entity.name).toBe('p1');
  });

  it('should map entity to template', () => {
    const entity = new Project(
      '1',
      'p1',
      'desc',
      'img',
      'web',
      true,
      { type: 'FeatureCollection', features: [] } as any,
      [],
      [],
      'o1',
      null,
      GamificationStrategy.BASIC,
      LeaderboardStrategy.POINTS_FIRST,
      RecommendationStrategy.SIMPLE,
      false,
    );
    const result = ProjectMapper.toTemplate(entity);
    expect(result.name).toBe('p1');
    expect(result.ownerId).toBe('o1');
  });
});
