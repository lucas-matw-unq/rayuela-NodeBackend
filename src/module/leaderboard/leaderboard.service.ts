import { Injectable } from '@nestjs/common';
import { LeaderboardDao } from './persistence/leaderboard.dao';
import { Leaderboard } from './persistence/leaderboard-user-schema';

@Injectable()
export class LeaderboardService {
  constructor(private leaderboardDao: LeaderboardDao) {}

  async getLeaderboardFor(projectId: string): Promise<Leaderboard> {
    return this.leaderboardDao.findByProjectId(projectId);
  }
}
