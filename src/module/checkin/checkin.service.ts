import { Injectable } from '@nestjs/common';
import { CreateCheckinDto } from './dto/create-checkin.dto';
import { UpdateCheckinDto } from './dto/update-checkin.dto';
import { CheckInDao } from './persistence/checkin.dao';
import { TaskService } from '../task/task.service';
import { Task } from '../task/entities/task.entity';
import { Checkin } from './entities/checkin.entity';
import { UserService } from '../auth/users/user.service';
import { Move } from './entities/move.entity';
import { GameBuilder } from './entities/game.entity';
import { ProjectService, UserStatus } from '../project/project.service';
import { MoveDao } from './persistence/move.dao';
import { GamificationService } from '../gamification/gamification.service';
import { Project } from '../project/entities/project';
import { User } from '../auth/users/user.entity';
import { GamificationEngineFactory } from '../gamification/entities/engine/gamification/gamification-strategy-factory';

@Injectable()
export class CheckinService {
  constructor(
    private readonly checkInDao: CheckInDao,
    private readonly moveDao: MoveDao,
    private readonly taskService: TaskService,
    private readonly userService: UserService,
    private readonly projectService: ProjectService,
    private readonly gamificationService: GamificationService,
    private readonly gamificationFactory: GamificationEngineFactory,
  ) {}

  async create(createCheckinDto: CreateCheckinDto) {
    const { tasks, user, users, checkin, project } =
      await this.getDataFromDB(createCheckinDto);

    const game = this.buildGame(tasks, users, project);

    checkin.contributesTo = tasks
      .find((t) => t.accept(checkin) && !t.solved)
      ?.getId();
    const gameStatus = game.play(checkin);
    const move = new Move(checkin, gameStatus);

    user.addBadgeFromProject(
      gameStatus.newBadges.map((b) => b.name),
      createCheckinDto.projectId,
    );

    const c = await this.checkInDao.create(checkin);
    checkin.id = c['_id'];
    await this.moveDao.create(move);
    const contribution = tasks.find(
      (t) => t.getId() === move.checkin.contributesTo,
    );

    if (contribution) {
      contribution.setSolved(true);
      user.addContribution(contribution.getId());
      await this.taskService.setTaskAsSolved(contribution.getId());
    }

    await this.userService.update(user.id, user);
    await this.gamificationService.saveMove(move);

    return {
      id: move.checkin.id,
      ...move,
      contributesTo: contribution && {
        name: contribution.name,
        id: contribution.getId(),
      },
    };
  }

  private buildGame(
    tasks: Task[],
    users: User[],
    project: Project & { user?: UserStatus },
  ) {
    const badgeEngine = this.gamificationFactory.getBadgeEngine(
      project.gamificationStrategy,
    );
    const pointsEngine = this.gamificationFactory.getPointsEngine(
      project.gamificationStrategy,
    );
    const leaderboardEngine = this.gamificationFactory.getLeaderboardEngine(
      project.gamificationStrategy,
    );
    return new GameBuilder()
      .withBadgeEngine(badgeEngine)
      .withPointsEngine(pointsEngine)
      .withLeaderboardEngine(leaderboardEngine)
      .withTasks(tasks)
      .withUsers(users)
      .withProject(project)
      .build();
  }

  async findAll() {
    return this.checkInDao.findAll();
  }

  async findOne(id: string) {
    return this.checkInDao.findOne(id);
  }

  async update(id: string, updateCheckinDto: UpdateCheckinDto) {
    return this.checkInDao.update(id, updateCheckinDto);
  }

  async remove(id: string) {
    return this.checkInDao.remove(id);
  }

  findByProjectId(userId: string, projectId: string) {
    return this.checkInDao.findByProjectId(userId, projectId);
  }

  private async getDataFromDB(createCheckinDto: CreateCheckinDto) {
    const tasks: Task[] = await this.taskService.findByProjectId(
      createCheckinDto.projectId,
    );
    const user = await this.userService.getByUserId(createCheckinDto.userId);
    const users = await this.userService.findAllByProjectId(
      createCheckinDto.projectId,
    );
    const checkin = Checkin.fromDTO(createCheckinDto, user);
    const project = await this.projectService.findOne(
      createCheckinDto.projectId,
    );
    return { tasks, user, users, checkin, project };
  }

  async rate(params: { checkinId: string; rate: number; userId: string }) {
    const ch = await this.findOne(params.checkinId);
    return this.userService.rate(params.userId, ch, params.rate);
  }
}
