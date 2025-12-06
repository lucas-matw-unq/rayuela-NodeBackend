import { Task } from './entities/task.entity';
import { TimeInterval } from './entities/time-restriction.entity';
import { Feature } from '../project/dto/create-project.dto';

class TaskBuilder {
  private id: string;
  private name: string;
  private description: string;
  private projectId: string;
  private timeRestriction: TimeInterval;
  private area: Feature;
  private type: string;
  private solved: boolean;

  constructor() {
    this.id = 'default-task-id';
    this.name = 'Default Task';
    this.description = 'Default task description';
    this.projectId = 'default-project-id';
    this.timeRestriction = new TimeInterval(
      'daily',
      [],
      { start: '00:00', end: '23:59' },
      new Date(),
      new Date(),
    );
    this.area = null;
    this.type = 'default-type';
    this.solved = false;
  }

  withId(id: string): this {
    this.id = id;
    return this;
  }

  withName(name: string): this {
    this.name = name;
    return this;
  }

  withDescription(description: string): this {
    this.description = description;
    return this;
  }

  withProjectId(projectId: string): this {
    this.projectId = projectId;
    return this;
  }

  withTimeRestriction(timeRestriction: TimeInterval): this {
    this.timeRestriction = timeRestriction;
    return this;
  }

  withArea(area: Feature): this {
    this.area = area;
    return this;
  }

  withType(type: string): this {
    this.type = type;
    return this;
  }

  withSolved(solved: boolean): this {
    this.solved = solved;
    return this;
  }

  build(): Task {
    return new Task(
      this.id,
      this.name,
      this.description,
      this.projectId,
      this.timeRestriction,
      this.area,
      this.type,
      this.solved,
    );
  }
}

export default new TaskBuilder();
