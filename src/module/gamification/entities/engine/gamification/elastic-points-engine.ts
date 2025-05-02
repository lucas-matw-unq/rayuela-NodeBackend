import { Game, PointsEngine } from '../../../../checkin/entities/game.entity';
import { Project } from '../../../../project/entities/project';
import { GamificationStrategy } from '../../../../project/dto/create-project.dto';
import { Checkin } from '../../../../checkin/entities/checkin.entity';
import { BasicPointsEngine } from './basic-points-engine';

export class ElasticPointsEngine implements PointsEngine {
  reward(ch: Checkin, game: Game): number {
    const user = ch.user;
    const users = game.users; // Lista de usuarios en el juego

    const totalContributions = users.reduce(
      (sum, u) => sum + (u.contributions.length || 0),
      0,
    );
    const userContributions = user.contributions.length || 0;

    const maxPoints = Math.max(
      ...users.map((u) => u.getGameProfileFromProject(game.project.id).points),
    );
    const userPoints = user.getGameProfileFromProject(game.project.id).points;

    // Cálculo de "a" (nivel de compromiso)
    const a =
      totalContributions > 0 ? userContributions / totalContributions : 0;

    // Cálculo de "d" (distancia normalizada al primero)
    const d = maxPoints > 0 ? (maxPoints - userPoints) / maxPoints : 0;

    // Cálculo del peso w
    const w = 1 + a * d;

    // Puntuación base
    const basePoints = new BasicPointsEngine().reward(ch, game);

    return Math.ceil(basePoints * w);
  }

  assignableTo(project: Project): boolean {
    return project.gamificationStrategy === GamificationStrategy.ELASTIC;
  }
}
