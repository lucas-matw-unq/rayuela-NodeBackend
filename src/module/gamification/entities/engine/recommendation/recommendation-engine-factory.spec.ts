import { Test, TestingModule } from '@nestjs/testing';
import { RecommendationEngineFactory } from './recommendation-engine-factory';
import { AdaptiveRecommendationEngine } from './adaptive-recommendation-engine';
import { SimpleRecommendationEngine } from './simple-recommendation-engine';
import { RecommendationStrategy } from '../../../../project/dto/create-project.dto';

describe('RecommendationEngineFactory', () => {
    let factory: RecommendationEngineFactory;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                RecommendationEngineFactory,
                { provide: AdaptiveRecommendationEngine, useValue: {} },
                { provide: SimpleRecommendationEngine, useValue: {} },
            ],
        }).compile();

        factory = module.get<RecommendationEngineFactory>(RecommendationEngineFactory);
    });

    it('should return correct engines', () => {
        expect(factory.getEngine(RecommendationStrategy.ADAPTIVE)).toBeDefined();
        expect(factory.getEngine(RecommendationStrategy.SIMPLE)).toBeDefined();
    });

    it('should throw for unknown strategy', () => {
        expect(() => factory.getEngine('UNKNOWN')).toThrow();
    });
});
