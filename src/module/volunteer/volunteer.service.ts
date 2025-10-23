import { Injectable } from '@nestjs/common';
import { UserJWT } from '../auth/auth.service';
import { UserService } from '../auth/users/user.service';
import { ProjectService } from '../project/project.service';
import { ProjectTemplate } from '../project/persistence/project.schema';
import { User } from '../auth/users/user.entity';

@Injectable()
export class VolunteerService {
  constructor(
    private readonly userService: UserService,
    private readonly projectService: ProjectService,
  ) {}

  async subscribeToProject(user: UserJWT, projectId: string) {
    const dbUser: User = await this.userService.getByUserId(user.userId);

    if (dbUser.isSubscribedToProject(projectId)) {
      dbUser.unsubscribeFromProject(projectId);
    } else {
      dbUser.subscribeToProject(projectId);
    }
    return this.userService.update(user.userId, dbUser);
  }

  async findProjects(userId) {
    const user = await this.userService.getByUserId(userId);
    const projects = await this.projectService.findAll();
    return this.sortSubscriptions(this.mapSubscriptions(projects, user));
  }

  private mapSubscriptions(
    projects: (ProjectTemplate & { _id: string })[],
    user: User,
  ) {
    return projects.map((p) => {
      return {
        ...p,
        subscribed: Boolean(
          user?.gameProfiles?.find(
            (gp) => gp.projectId === p._id.toString() && gp.active,
          ),
        ),
      };
    });
  }

  private sortSubscriptions(subs) {
    return subs.sort((a, b) => {
      // Si `a.subscribed` es true y `b.subscribed` es false, a se coloca primero
      return a.subscribed === b.subscribed ? 0 : a.subscribed ? -1 : 1;
    });
  }

  findPublicProjects() {
    return this.projectService.findAll();
  }
}
