import { Project } from '../../project/entities/project';
import { Checkin } from './checkin.entity';
import { Task } from '../../task/entities/task.entity';
import { User } from '../../auth/users/user.entity';
import { BadgeRule } from '../../gamification/entities/gamification.entity';

interface Engine {
  assignableTo(project: Project): boolean;
}

export interface PointsEngine extends Engine {
  reward(ch: Checkin, game: Game): number;
}

export interface BadgeEngine extends Engine {
  newBadgesFor(u: User, ch: Checkin, project: Project): BadgeRule[]; // Badge's names
}

export interface LeaderboardUser {
  _id: string;
  username: string;
  completeName: string;
  points: number;
  badges: string[];
}

export interface LeaderboardEngine extends Engine {
  build(usersList: User[], u: User, project: Project): LeaderboardUser[];
}

export interface GameStatus {
  newBadges: BadgeRule[];
  newLeaderboard: LeaderboardUser[];
  newPoints: number;
}

export class Game {
  set users(value: User[]) {
    this._users = value;
  }

  get users(): User[] {
    return this._users;
  }

  get project(): Project {
    return this._project;
  }

  private leaderboardEngine: LeaderboardEngine;
  private _project: Project;
  private pointsEngine: PointsEngine;
  private badgeEngine: BadgeEngine;
  private tasks: Task[];
  private _users: User[];

  constructor(
    project: Project,
    pointsEngine: PointsEngine,
    badgeEngine: BadgeEngine,
    leaderboardEngine: LeaderboardEngine,
    tasks: Task[],
    users: User[],
  ) {
    this._project = project;
    this.pointsEngine = pointsEngine;
    this.badgeEngine = badgeEngine;
    this.leaderboardEngine = leaderboardEngine;
    this.tasks = tasks;
    this._users = users;
  }

  play(checkin: Checkin): GameStatus {
    const newPoints = this.pointsEngine.reward(checkin, this);
    checkin.user.addPointsFromProject(newPoints, this._project.id);
    return {
      newBadges: this.badgeEngine.newBadgesFor(
        checkin.user,
        checkin,
        this._project,
      ),
      newPoints,
      newLeaderboard: this.leaderboardEngine.build(
        this._users,
        checkin.user,
        this._project,
      ),
    };
  }
}

export class GameBuilder {
  private project: Project | null = null;
  private tasks: Task[] | null = null;
  private users: User[] | null = null;
  private pointsEngine: PointsEngine;
  private badgeEngine: BadgeEngine;
  private leaderboardEngine: LeaderboardEngine;

  withPointsEngine(pointsEngine: PointsEngine): this {
    this.pointsEngine = pointsEngine;
    return this;
  }

  withBadgeEngine(badgeEngine: BadgeEngine): this {
    this.badgeEngine = badgeEngine;
    return this;
  }

  withLeaderboardEngine(leaderboardEngine: LeaderboardEngine): this {
    this.leaderboardEngine = leaderboardEngine;
    return this;
  }

  withProject(project: Project): this {
    this.project = project;
    return this;
  }

  withTasks(tasks: Task[]): this {
    this.tasks = tasks;
    return this;
  }

  withUsers(users: User[]): this {
    this.users = users;
    return this;
  }

  build(): Game {
    if (
      !this.project ||
      !this.pointsEngine ||
      !this.badgeEngine ||
      !this.leaderboardEngine
    ) {
      throw new Error(
        'All dependencies must be provided before building the Game instance',
      );
    }
    return new Game(
      this.project,
      this.pointsEngine,
      this.badgeEngine,
      this.leaderboardEngine,
      this.tasks,
      this.users,
    );
  }
}
