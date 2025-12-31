import { SimpleRecommendationEngine } from './simple-recommendation-engine';

describe('SimpleRecommendationEngine', () => {
  it('should return all tasks with rating 0', () => {
    const engine = new SimpleRecommendationEngine();
    const tasks = [{ id: '1' }, { id: '2' }] as any;
    const result = engine.generateRecommendations({} as any, {}, tasks);
    expect(result.length).toBe(2);
    expect(result[0].estimatedRating).toBe(0);
  });
});
