import {
  LeaderboardEngine,
  LeaderboardUser,
} from '../../../../checkin/entities/game.entity';
import { User } from '../../../../auth/users/user.entity';
import { Project } from '../../../../project/entities/project';
import { LeaderboardStrategy } from '../../../../project/dto/create-project.dto';
import { mapLeaderboardUser } from './badge-first-leaderboard-engine';

export class PointsFirstLBEngine implements LeaderboardEngine {
  assignableTo(project: Project): boolean {
    return project.leaderboardStrategy === LeaderboardStrategy.POINTS_FIRST;
  }

  build(usersList: User[], u: User, project: Project): LeaderboardUser[] {
    return usersList
      .sort(
        (a, b) =>
          b.getGameProfileFromProject(project.id).points -
          a.getGameProfileFromProject(project.id).points,
      )
      .map(mapLeaderboardUser(u, project));
  }
}
