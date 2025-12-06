import { Checkin } from './entities/checkin.entity';
import { User } from '../auth/users/user.entity';
import { Task } from '../task/entities/task.entity';

class CheckinBuilder {
  private id: string;
  private latitude: string;
  private longitude: string;
  private datetime: Date;
  private projectId: string;
  private user: User;
  private taskType: string;
  private relatedTask: Task;

  constructor() {
    this.id = 'default-checkin-id';
    this.latitude = '0';
    this.longitude = '0';
    this.datetime = new Date();
    this.projectId = 'default-project-id';
    this.user = new User(
      'default@user.com',
      'defaultuser',
      'password',
      'Default User',
    );
    this.taskType = 'default-task-type';
    this.relatedTask = null;
  }

  withId(id: string): this {
    this.id = id;
    return this;
  }

  withLatitude(latitude: string): this {
    this.latitude = latitude;
    return this;
  }

  withLongitude(longitude: string): this {
    this.longitude = longitude;
    return this;
  }

  withDatetime(datetime: Date): this {
    this.datetime = datetime;
    return this;
  }

  withProjectId(projectId: string): this {
    this.projectId = projectId;
    return this;
  }

  withUser(user: User): this {
    this.user = user;
    return this;
  }

  withTaskType(taskType: string): this {
    this.taskType = taskType;
    return this;
  }

  withRelatedTask(relatedTask: Task): this {
    this.relatedTask = relatedTask;
    return this;
  }

  build(): Checkin {
    return new Checkin(
      this.latitude,
      this.longitude,
      this.datetime,
      this.projectId,
      this.user,
      this.taskType,
      this.id,
      this.relatedTask,
    );
  }
}

export default new CheckinBuilder();
