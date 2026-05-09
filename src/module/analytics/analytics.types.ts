export type Granularity = 'day' | 'week' | 'month';

export interface TimeSeries {
  period: string; // ISO date string of the bucket start
  count: number;
}

export interface ActiveUsersSeries {
  period: string;
  uniqueUsers: number;
}

export interface StrategyBreakdown {
  gamificationStrategy: string;
  recommendationStrategy: string;
  leaderboardStrategy: string;
  projectId: string;
  projectName: string;
  checkinCount: number;
  avgPointsPerCheckin: number;
  activeUsers: number;
}

export interface PointsSeries {
  period: string;
  totalPoints: number;
  avgPointsPerCheckin: number;
}

export interface ContributionRate {
  projectId: string;
  projectName: string;
  total: number;
  withContribution: number;
  rate: number; // 0–1
}

export interface SummaryStats {
  totalCheckins: number;
  totalActiveUsers: number; // users with at least 1 checkin
  overallContributionRate: number;
  totalBadgesEarned: number;
  totalPointsAwarded: number;
}
