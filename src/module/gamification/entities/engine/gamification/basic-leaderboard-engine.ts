import {
  LeaderboardEngine,
  LeaderboardUser,
} from '../../../../checkin/entities/game.entity';
import { User } from '../../../../auth/users/user.entity';
import { Project } from '../../../../project/entities/project';
import { GamificationStrategy } from '../../../../project/dto/create-project.dto';

export class BasicLeaderbardEngine implements LeaderboardEngine {
  assignableTo(project: Project): boolean {
    return project.gamificationStrategy === GamificationStrategy.BASIC;
  }

  build(usersList: User[], u: User, project: Project): LeaderboardUser[] {
    return usersList
      .sort(
        (a, b) =>
          b.getGameProfileFromProject(project.id).points -
          a.getGameProfileFromProject(project.id).points,
      )
      .map((us) => {
        if (us.id.toString() === u.id.toString()) {
          return {
            username: u.username,
            _id: u.id,
            points: u.getGameProfileFromProject(project.id).points,
            badges: u.getGameProfileFromProject(project.id).badges,
            completeName: u.completeName,
          };
        } else {
          return {
            username: us.username,
            _id: us.id,
            points: us.getGameProfileFromProject(project.id).points,
            badges: us.getGameProfileFromProject(project.id).badges,
            completeName: us.completeName,
          };
        }
      });
  }
}
