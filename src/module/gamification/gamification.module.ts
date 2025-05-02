import { Module } from '@nestjs/common';
import { GamificationService } from './gamification.service';
import { GamificationController } from './gamificationController';
import { MongooseModule } from '@nestjs/mongoose';
import {
  GamificationTemplate,
  GamificationTemplateSchema,
} from './persistence/gamification.schema';
import { GamificationDao } from './persistence/gamification-dao.service';
import { AuthModule } from '../auth/auth.module';
import { LeaderboardModule } from '../leaderboard/leaderboard.module';
import { GamificationEngineFactory } from './entities/engine/gamification/gamification-strategy-factory';
import { SimpleRecommendationEngine } from './entities/engine/recommendation/simple-recommendation-engine';
import { AdaptiveRecommendationEngine } from './entities/engine/recommendation/adaptive-recommendation-engine';
import { ElasticPointsEngine } from './entities/engine/gamification/elastic-points-engine';
import { BasicLeaderbardEngine } from './entities/engine/gamification/basic-leaderboard-engine';
import { BasicPointsEngine } from './entities/engine/gamification/basic-points-engine';
import { BasicBadgeEngine } from './entities/engine/gamification/basic-badge-engine';

const engines = [
  GamificationEngineFactory,
  SimpleRecommendationEngine,
  AdaptiveRecommendationEngine,
  ElasticPointsEngine,
  BasicLeaderbardEngine,
  BasicPointsEngine,
  BasicBadgeEngine,
];

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: GamificationTemplate.collectionName(),
        schema: GamificationTemplateSchema,
      },
    ]),
    AuthModule,
    LeaderboardModule,
  ],
  exports: [GamificationService, GamificationDao, ...engines],
  controllers: [GamificationController],
  providers: [GamificationService, GamificationDao, ...engines],
})
export class GamificationModule {}
