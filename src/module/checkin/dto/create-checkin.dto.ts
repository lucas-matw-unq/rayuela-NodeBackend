export class CreateCheckinDto {
  latitude: string;
  longitude: string;
  datetime: Date;
  projectId: string;
  userId: string;
  taskType: string;
  imageRefs?: string[];

  constructor({
    datetime,
    latitude,
    projectId,
    userId,
    longitude,
    taskType,
    imageRefs,
  }: CreateCheckinDto) {
    this.datetime = datetime;
    this.latitude = latitude;
    this.longitude = longitude;
    this.userId = userId;
    this.projectId = projectId;
    this.taskType = taskType;
    this.imageRefs = imageRefs;
  }

}
