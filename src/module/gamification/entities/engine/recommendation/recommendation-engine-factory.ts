import { Injectable } from '@nestjs/common';
import { AdaptiveRecommendationEngine } from './adaptive-recommendation-engine';
import { SimpleRecommendationEngine } from './simple-recommendation-engine';
import { IRecommendationEngine } from './i-recommendation-engine';
import { RecommendationStrategy } from '../../../../project/dto/create-project.dto';

@Injectable()
export class RecommendationEngineFactory {
  constructor(
    private readonly adaptiveEngine: AdaptiveRecommendationEngine,
    private readonly simpleEngine: SimpleRecommendationEngine,
  ) {}

  getEngine(strategy: string): IRecommendationEngine {
    switch (strategy) {
      case RecommendationStrategy.ADAPTIVE:
        return this.adaptiveEngine;
      case RecommendationStrategy.SIMPLE:
        return this.simpleEngine;
      default:
        throw new Error(`Unknown strategy: ${strategy}`);
    }
  }
}
