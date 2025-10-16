import { Checkin } from '../../checkin/entities/checkin.entity';
import { GeoUtils } from '../utils/geoUtils';
import { TimeInterval } from './time-restriction.entity';
import { Feature } from '../../project/dto/create-project.dto';

export class Task {
  get solved(): boolean {
    return this.#solved;
  }

  get timeInterval(): TimeInterval {
    return this.#timeInterval;
  }

  get type(): string {
    return this.#type;
  }

  get areaGeoJSON(): Feature {
    return this.#areaGeoJSON;
  }

  get description(): string {
    return this.#description;
  }

  get name(): string {
    return this.#name;
  }

  get projectId(): string {
    return this.#projectId;
  }

  getId(): string {
    return this.#_id;
  }

  #_id: string;
  #name: string;
  #description: string;
  #projectId: string;
  #timeInterval: TimeInterval;
  #areaGeoJSON: Feature;
  #type: string;
  #solved: boolean = false;

  constructor(
    id: string,
    name: string,
    description: string,
    projectId: string,
    timeRestriction: TimeInterval,
    area: Feature,
    type: string,
    solved: boolean = false,
  ) {
    this.#_id = id;
    this.#name = name;
    this.#description = description;
    this.#projectId = projectId;
    this.#timeInterval = timeRestriction;
    this.#areaGeoJSON = area;
    this.#type = type;
    this.#solved = solved;
  }

  accept(checkin: Checkin) {
    const validations = [
      this.isSameTaskType(checkin),
      this.isSameProject(checkin),
      this.isValidTimeRestriction(checkin.date),
      this.isValidArea(checkin),
    ];
    return validations.every((v) => v);
  }

  private isValidTimeRestriction(date: Date): boolean {
    return this.#timeInterval.satisfy(date);
  }

  private isSameProject(checkin: Checkin) {
    return checkin.projectId === this.#projectId;
  }

  private isValidArea(checkin: Checkin) {
    return GeoUtils.isPointInPolygon(
      parseFloat(checkin.longitude),
      parseFloat(checkin.latitude),
      this.#areaGeoJSON.geometry,
    );
  }

  private isSameTaskType(checkin: Checkin) {
    return this.#type === checkin.taskType;
  }

  setSolved(solved: boolean) {
    this.#solved = solved;
  }

  toJSON() {
    return {
      id: this.#_id,
      name: this.#name,
      description: this.#description,
      projectId: this.#projectId,
      timeInterval: this.#timeInterval,
      areaGeoJSON: this.#areaGeoJSON,
      type: this.#type,
      solved: this.#solved,
    };
  }

  contributesToCheckin(checkin: Checkin) {
    return this.accept(checkin) && !this.solved;
  }
}
