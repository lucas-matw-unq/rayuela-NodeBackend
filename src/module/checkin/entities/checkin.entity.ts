import { CreateCheckinDto } from '../dto/create-checkin.dto';
import { User } from '../../auth/users/user.entity';
import { Task } from '../../task/entities/task.entity';

export class Checkin {
  get relatedTask(): Task {
    return this._relatedTask;
  }

  set relatedTask(value: Task) {
    this._relatedTask = value;
  }

  set user(value: User) {
    this.#user = value;
  }

  set contributesTo(value: string) {
    this.#contributesTo = value;
  }

  set id(value: string) {
    this.#id = value;
  }

  get id(): string {
    return this.#id;
  }

  get taskType(): string {
    return this.#taskType;
  }

  set date(value: Date) {
    this.#date = value;
  }

  set projectId(value: string) {
    this.#projectId = value;
  }

  get contributesTo(): string {
    return this.#contributesTo;
  }

  get user(): User {
    return this.#user;
  }

  get longitude(): string {
    return this.#longitude;
  }

  get latitude(): string {
    return this.#latitude;
  }

  get projectId(): string {
    return this.#projectId;
  }

  get date(): Date {
    return this.#date;
  }

  get imageRef(): string {
    return this.#imageRef;
  }

  set imageRef(value: string) {
    this.#imageRef = value;
  }

  #latitude: string;
  #longitude: string;
  #date: Date;
  #projectId: string;
  #user: User;
  #contributesTo: string;
  #taskType: string;
  #id: string;
  #imageRef: string;
  private _relatedTask: Task;

  constructor(
    latitude: string,
    longitude: string,
    datetime: Date,
    projectId: string,
    user: User,
    taskType: string,
    id: string,
    relatedTask?: Task,
    imageRef?: string,
  ) {
    this.#latitude = latitude;
    this.#longitude = longitude;
    this.#date = datetime;
    this.#projectId = projectId;
    this.#user = user;
    this.#taskType = taskType;
    this._relatedTask = relatedTask;
    this.#contributesTo = '';
    this.#id = id;
    this.#imageRef = imageRef || '';
  }


  validateContribution(id: string): void {
    this.#contributesTo = id;
  }

  static fromDTO(createCheckinDto: CreateCheckinDto, user: User): Checkin {
    return new Checkin(
      createCheckinDto.latitude,
      createCheckinDto.longitude,
      createCheckinDto.datetime,
      createCheckinDto.projectId,
      user,
      createCheckinDto.taskType,
      '',
    );
  }
}
