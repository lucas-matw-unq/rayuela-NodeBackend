import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Document } from 'mongoose';
import { CheckInDocument, CheckInTemplate } from '../checkin/persistence/checkin.schema';
import { MoveDocument, MoveTemplate } from '../checkin/persistence/move.schema';
import { ProjectDocument, ProjectTemplate } from '../project/persistence/project.schema';
import { UserDocument, UserTemplate } from '../auth/users/user.schema';
import {
  ActiveUsersSeries,
  ContributionRate,
  Granularity,
  PointsSeries,
  StrategyBreakdown,
  SummaryStats,
  TimeSeries,
} from './analytics.types';

@Injectable()
export class AnalyticsDao {
  constructor(
    @InjectModel(CheckInTemplate.collectionName())
    private readonly checkinModel: Model<CheckInDocument>,

    @InjectModel(MoveTemplate.collectionName())
    private readonly moveModel: Model<MoveDocument>,

    @InjectModel(ProjectTemplate.collectionName())
    private readonly projectModel: Model<ProjectDocument>,

    @InjectModel(UserTemplate.collectionName())
    private readonly userModel: Model<UserDocument>,
  ) {}

  private buildDateBucket(granularity: Granularity, field: string) {
    const d = `$${field}`;
    if (granularity === 'day') {
      return { $dateToString: { format: '%Y-%m-%d', date: d } };
    }
    if (granularity === 'week') {
      return {
        $dateFromParts: {
          isoWeekYear: { $isoWeekYear: d },
          isoWeek: { $isoWeek: d },
          isoDayOfWeek: 1,
        },
      };
    }
    return { $dateToString: { format: '%Y-%m-01', date: d } };
  }

  private lookupByStringId(from: string, localField: string, as: string) {
    return {
      $lookup: {
        from,
        let: { refId: `$${localField}` },
        pipeline: [
          { $match: { $expr: { $eq: [{ $toString: '$_id' }, '$$refId'] } } },
        ],
        as,
      },
    };
  }

  private projectMatch(projectId?: string) {
    return projectId ? [{ $match: { projectId } }] : [];
  }

  async checkinsOverTime(projectId: string | undefined, granularity: Granularity): Promise<TimeSeries[]> {
    return this.checkinModel.aggregate([
      ...this.projectMatch(projectId),
      {
        $group: {
          _id: this.buildDateBucket(granularity, 'datetime'),
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
      { $project: { _id: 0, period: '$_id', count: 1 } },
    ]);
  }

  async activeUsersOverTime(projectId: string | undefined, granularity: Granularity): Promise<ActiveUsersSeries[]> {
    return this.checkinModel.aggregate([
      ...this.projectMatch(projectId),
      {
        $group: {
          _id: {
            period: this.buildDateBucket(granularity, 'datetime'),
            userId: '$userId',
          },
        },
      },
      {
        $group: {
          _id: '$_id.period',
          uniqueUsers: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
      { $project: { _id: 0, period: '$_id', uniqueUsers: 1 } },
    ]);
  }

  async byStrategy(): Promise<StrategyBreakdown[]> {
    return this.checkinModel.aggregate([
      this.lookupByStringId('projects', 'projectId', 'project'),
      { $unwind: '$project' },
      {
        $lookup: {
          from: 'moves',
          let: { cid: { $toString: '$_id' } },
          pipeline: [
            { $match: { $expr: { $eq: ['$checkinId', '$$cid'] } } },
          ],
          as: 'move',
        },
      },
      { $unwind: { path: '$move', preserveNullAndEmptyArrays: true } },
      {
        $group: {
          _id: '$projectId',
          projectName: { $first: '$project.name' },
          gamificationStrategy: { $first: '$project.gamificationStrategy' },
          recommendationStrategy: { $first: '$project.recommendationStrategy' },
          leaderboardStrategy: { $first: '$project.leaderboardStrategy' },
          checkinCount: { $sum: 1 },
          totalPoints: { $sum: { $ifNull: ['$move.newPoints', 0] } },
          users: { $addToSet: '$userId' },
        },
      },
      {
        $project: {
          _id: 0,
          projectId: '$_id',
          projectName: 1,
          gamificationStrategy: 1,
          recommendationStrategy: 1,
          leaderboardStrategy: 1,
          checkinCount: 1,
          avgPointsPerCheckin: {
            $cond: [
              { $eq: ['$checkinCount', 0] },
              0,
              { $divide: ['$totalPoints', '$checkinCount'] },
            ],
          },
          activeUsers: { $size: '$users' },
        },
      },
    ]);
  }

  async pointsOverTime(projectId: string | undefined, granularity: Granularity): Promise<PointsSeries[]> {
    return this.moveModel.aggregate([
      ...(projectId
        ? [
            this.lookupByStringId('checkins', 'checkinId', 'checkin'),
            { $unwind: '$checkin' },
            { $match: { 'checkin.projectId': projectId } },
          ]
        : []),
      {
        $group: {
          _id: this.buildDateBucket(granularity, 'timestamp'),
          totalPoints: { $sum: '$newPoints' },
          checkinCount: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
      {
        $project: {
          _id: 0,
          period: '$_id',
          totalPoints: 1,
          avgPointsPerCheckin: {
            $cond: [
              { $eq: ['$checkinCount', 0] },
              0,
              { $divide: ['$totalPoints', '$checkinCount'] },
            ],
          },
        },
      },
    ]);
  }

  async contributionRate(projectId?: string): Promise<ContributionRate[]> {
    return this.checkinModel.aggregate([
      ...this.projectMatch(projectId),
      {
        $group: {
          _id: '$projectId',
          total: { $sum: 1 },
          withContribution: {
            $sum: { $cond: [{ $gt: [{ $strLenCP: '$contributesTo' }, 0] }, 1, 0] },
          },
        },
      },
      {
        $lookup: {
          from: 'projects',
          let: { pid: '$_id' },
          pipeline: [
            { $match: { $expr: { $eq: [{ $toString: '$_id' }, '$$pid'] } } },
          ],
          as: 'project',
        },
      },
      { $unwind: '$project' },
      {
        $project: {
          _id: 0,
          projectId: '$_id',
          projectName: '$project.name',
          total: 1,
          withContribution: 1,
          rate: {
            $cond: [
              { $eq: ['$total', 0] },
              0,
              { $divide: ['$withContribution', '$total'] },
            ],
          },
        },
      },
    ]);
  }

  async badgeAcquisitionOverTime(projectId: string | undefined, granularity: Granularity): Promise<TimeSeries[]> {
    return this.moveModel.aggregate([
      ...(projectId
        ? [
            this.lookupByStringId('checkins', 'checkinId', 'checkin'),
            { $unwind: '$checkin' },
            { $match: { 'checkin.projectId': projectId } },
          ]
        : []),
      { $unwind: '$newBadges' },
      {
        $group: {
          _id: this.buildDateBucket(granularity, 'timestamp'),
          count: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
      { $project: { _id: 0, period: '$_id', count: 1 } },
    ]);
  }

  async summary(projectId?: string): Promise<SummaryStats> {
    const [checkins, activeUsers, badgesResult, pointsResult] = await Promise.all([
      this.checkinModel.countDocuments(projectId ? { projectId } : {}),
      this.checkinModel.distinct('userId', projectId ? { projectId } : {}),
      this.moveModel.aggregate([
        ...(projectId
          ? [
              this.lookupByStringId('checkins', 'checkinId', 'checkin'),
              { $unwind: '$checkin' },
              { $match: { 'checkin.projectId': projectId } },
            ]
          : []),
        { $unwind: '$newBadges' },
        { $count: 'total' },
      ]),
      this.moveModel.aggregate([
        ...(projectId
          ? [
              this.lookupByStringId('checkins', 'checkinId', 'checkin'),
              { $unwind: '$checkin' },
              { $match: { 'checkin.projectId': projectId } },
            ]
          : []),
        { $group: { _id: null, total: { $sum: '$newPoints' } } },
      ]),
    ]);

    const contributionData = await this.contributionRate(projectId);
    const totalContrib = contributionData.reduce((s, p) => s + p.withContribution, 0);
    const totalAll = contributionData.reduce((s, p) => s + p.total, 0);

    return {
      totalCheckins: checkins,
      totalActiveUsers: activeUsers.length,
      overallContributionRate: totalAll === 0 ? 0 : totalContrib / totalAll,
      totalBadgesEarned: badgesResult[0]?.total ?? 0,
      totalPointsAwarded: pointsResult[0]?.total ?? 0,
    };
  }
}
