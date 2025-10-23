import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { LeaderboardService } from './leaderboard.service';
import { JwtAuthGuard } from '../auth/auth.guard';

@Controller('leaderboard')
export class LeaderboardController {
  constructor(private readonly leaderboardService: LeaderboardService) {}

  @UseGuards(JwtAuthGuard)
  @Get('/:projectId')
  leaderboard(@Param('projectId') projectId: string) {
    return this.leaderboardService.getLeaderboardFor(projectId);
  }
}
