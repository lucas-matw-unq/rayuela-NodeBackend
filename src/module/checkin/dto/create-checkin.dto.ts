export class CreateCheckinDto {
  latitude: string;
  longitude: string;
  datetime: Date;
  projectId: string;
  userId: string;
  taskType: string;
  imageRef?: string;

  constructor({
    datetime,
    latitude,
    projectId,
    userId,
    longitude,
    taskType,
    imageRef,
  }: CreateCheckinDto) {
    this.datetime = datetime;
    this.latitude = latitude;
    this.longitude = longitude;
    this.userId = userId;
    this.projectId = projectId;
    this.taskType = taskType;
    this.imageRef = imageRef;
  }

}
