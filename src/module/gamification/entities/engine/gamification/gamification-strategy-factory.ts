import { Injectable } from '@nestjs/common';
import {
  BadgeEngine,
  LeaderboardEngine,
  PointsEngine,
} from '../../../../checkin/entities/game.entity';
import { GamificationStrategy } from '../../../../project/dto/create-project.dto';
import { BasicPointsEngine } from './basic-points-engine';
import { ElasticPointsEngine } from './elastic-points-engine';
import { BasicLeaderbardEngine } from './basic-leaderboard-engine';
import { BasicBadgeEngine } from './basic-badge-engine';

@Injectable()
export class GamificationEngineFactory {
  constructor(
    private readonly basicPointEngine: BasicPointsEngine,
    private readonly elasticPointEngine: ElasticPointsEngine,
    private readonly leaderboardEngine: BasicLeaderbardEngine,
    private readonly basicBadgeEngine: BasicBadgeEngine,
  ) {}

  getBadgeEngine(gamificationStrategy: GamificationStrategy): BadgeEngine {
    switch (gamificationStrategy) {
      case GamificationStrategy.BASIC:
        return this.basicBadgeEngine;
      default:
        throw new Error(
          `Unknown gamification engine type: ${gamificationStrategy}`,
        );
    }
  }

  getPointsEngine(gamificationStrategy: GamificationStrategy): PointsEngine {
    switch (gamificationStrategy) {
      case GamificationStrategy.BASIC:
        return this.basicPointEngine;
      case GamificationStrategy.ELASTIC:
        return this.elasticPointEngine;
      default:
        throw new Error(
          `Unknown gamification engine type: ${gamificationStrategy}`,
        );
    }
  }

  getLeaderboardEngine(
    gamificationStrategy: GamificationStrategy,
  ): LeaderboardEngine {
    switch (gamificationStrategy) {
      case GamificationStrategy.BASIC:
        return this.leaderboardEngine;
      default:
        throw new Error(
          `Unknown gamification engine type: ${gamificationStrategy}`,
        );
    }
  }
}
