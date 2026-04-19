import { Injectable } from '@nestjs/common';
import { AnalyticsDao } from './analytics.dao';
import { Granularity } from './analytics.types';

@Injectable()
export class AnalyticsService {
  constructor(private readonly analyticsDao: AnalyticsDao) {}

  getCheckinsOverTime(projectId?: string, granularity?: Granularity) {
    return this.analyticsDao.checkinsOverTime(projectId, granularity ?? 'week');
  }

  getActiveUsersOverTime(projectId?: string, granularity?: Granularity) {
    return this.analyticsDao.activeUsersOverTime(projectId, granularity ?? 'week');
  }

  getByStrategy() {
    return this.analyticsDao.byStrategy();
  }

  getPointsOverTime(projectId?: string, granularity?: Granularity) {
    return this.analyticsDao.pointsOverTime(projectId, granularity ?? 'week');
  }

  getContributionRate(projectId?: string) {
    return this.analyticsDao.contributionRate(projectId);
  }

  getBadgeAcquisitionOverTime(projectId?: string, granularity?: Granularity) {
    return this.analyticsDao.badgeAcquisitionOverTime(projectId, granularity ?? 'week');
  }

  getSummary() {
    return this.analyticsDao.summary();
  }
}
