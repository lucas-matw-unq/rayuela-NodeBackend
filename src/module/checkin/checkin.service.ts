import { ConflictException, Injectable, Logger } from '@nestjs/common';
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
import { StorageService } from '../storage/storage.service';
import { CheckinIdempotencyDao } from './persistence/checkin-idempotency.dao';

@Injectable()
export class CheckinService {
  private readonly logger = new Logger(CheckinService.name);

  constructor(
    private readonly checkInDao: CheckInDao,
    private readonly moveDao: MoveDao,
    private readonly taskService: TaskService,
    private readonly userService: UserService,
    private readonly projectService: ProjectService,
    private readonly gamificationService: GamificationService,
    private readonly gamificationFactory: GamificationEngineFactory,
    private readonly storageService: StorageService,
    private readonly idempotencyDao: CheckinIdempotencyDao,
  ) {}

  async create(params: {
    createCheckinDto: CreateCheckinDto;
    files?: Express.Multer.File[];
    /**
     * Optional `Idempotency-Key` value sent by the mobile outbox. When
     * present we look up the key first and replay the previous result
     * if it matches the same user; collisions across users get a 409.
     * See `docs/OFFLINE_SYNC_PLAN.md` §8 #1 for the rationale.
     */
    idempotencyKey?: string;
  }) {
    const { createCheckinDto, files, idempotencyKey } = params;

    if (idempotencyKey) {
      const claim = await this.idempotencyDao.claimKey(
        idempotencyKey,
        createCheckinDto.userId,
      );
      if (claim !== null) {
        // Key was already claimed by this user.
        if (!claim.checkinId) {
          // Another request is still processing — tell the client to retry.
          throw new ConflictException(
            'Idempotency-Key is already being processed, retry shortly',
          );
        }
        return this.replayFromHit(claim as { checkinId: string });
      }
      // claim === null → we won the race, proceed with create.
    }

    const { tasks, user, users, checkin, project } =
      await this.getDataFromDB(createCheckinDto);

    if (!project.available) {
      throw new ConflictException('The project is not running');
    }

    if (files && files.length > 0) {
      const uploadPromises = files.map((file) =>
        this.storageService.uploadFile(
          file,
          `checkins/${createCheckinDto.userId}`,
        ),
      );
      const imageRefs = await Promise.all(uploadPromises);
      checkin.imageRefs = imageRefs;
    }

    const game = this.buildGame(tasks, users, project);

    checkin.contributesTo = tasks
      .find((t) => t.contributesToCheckin(checkin))
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

    if (idempotencyKey) {
      await this.idempotencyDao.setCheckinId(
        idempotencyKey,
        String(checkin.id),
      );
    }

    return {
      ...this.buildCreateResponse(move, contribution),
    };
  }

  /**
   * Rehydrate the original check-in from an idempotency hit and return
   * the same response envelope `create` would have produced.
   * Game status is zeroed out — points/badges were already awarded on the
   * first call and must not be double-counted.
   */
  private async replayFromHit(hit: { checkinId: string }) {
    const original = await this.checkInDao.findOne(hit.checkinId);
    const contribution = original.contributesTo
      ? await this.taskService.findOne(original.contributesTo)
      : undefined;

    const replayMove = new Move(original, {
      newBadges: [],
      newPoints: 0,
      newLeaderboard: [],
    });

    return this.buildCreateResponse(replayMove, contribution, true);
  }

  private buildCreateResponse(
    move: Move,
    contribution?: Task,
    replayed = false,
  ) {
    return {
      id: move.checkin.id,
      ...move,
      ...(replayed ? { replayed } : {}),
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
      project.leaderboardStrategy,
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
