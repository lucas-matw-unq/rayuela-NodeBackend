import ProjectBuilder from './project.builder';
import {
  GamificationStrategy,
  LeaderboardStrategy,
  RecommendationStrategy,
} from './dto/create-project.dto';

describe('ProjectBuilder', () => {
  it('should build a project with custom values', () => {
    const project = ProjectBuilder.withId('1')
      .withName('Name')
      .withDescription('Desc')
      .withImage('img')
      .withWeb('web')
      .withAvailable(false)
      .withAreas({ type: 'FeatureCollection', features: [] } as any)
      .withTaskTypes(['type1'])
      .withTimeIntervals([])
      .withOwnerId('owner')
      .withGamification(null)
      .withGamificationStrategy(GamificationStrategy.ELASTIC)
      .withLeaderboardStrategy(LeaderboardStrategy.BADGES_FIRST)
      .withRecommendationStrategy(RecommendationStrategy.ADAPTIVE)
      .withManualLocation(true)
      .build();

    expect(project.id).toBe('1');
    expect(project.name).toBe('Name');
    expect(project.description).toBe('Desc');
    expect(project.image).toBe('img');
    expect(project.web).toBe('web');
    expect(project.available).toBe(false);
    expect(project.ownerId).toBe('owner');
    expect(project.gamificationStrategy).toBe(GamificationStrategy.ELASTIC);
    expect(project.leaderboardStrategy).toBe(LeaderboardStrategy.BADGES_FIRST);
    expect(project.recommendationStrategy).toBe(
      RecommendationStrategy.ADAPTIVE,
    );
    expect(project.manualLocation).toBe(true);
  });
});
