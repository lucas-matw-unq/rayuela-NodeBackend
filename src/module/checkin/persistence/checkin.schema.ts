import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type CheckInDocument = CheckInTemplate & Document;

@Schema()
export class CheckInTemplate {
  @Prop({ required: true, maxlength: 500 })
  latitude: string;

  @Prop({ required: true, maxlength: 500 })
  longitude: string;

  @Prop({ required: true, type: Date })
  datetime: Date;

  @Prop({ ref: 'Project', required: true })
  projectId: string;

  @Prop({ ref: 'User', required: true })
  userId: string;

  @Prop({ required: true })
  taskType: string;

  @Prop({ type: String, default: '' })
  contributesTo: string;

  constructor(
    latitude: string,
    longitude: string,
    datetime: Date,
    projectId: string,
    userId: string,
    contributesTo: string,
    taskType: string,
  ) {
    this.latitude = latitude;
    this.longitude = longitude;
    this.datetime = datetime;
    this.projectId = projectId;
    this.userId = userId;
    this.contributesTo = contributesTo;
    this.taskType = taskType;
  }

  static collectionName() {
    return 'Checkin';
  }
}

export const CheckInSchema = SchemaFactory.createForClass(CheckInTemplate);
