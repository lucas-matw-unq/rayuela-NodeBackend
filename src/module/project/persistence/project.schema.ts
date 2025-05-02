import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Schema as MongooseSchema } from 'mongoose';
import { TimeInterval } from '../../task/entities/time-restriction.entity';
import {
  GamificationStrategy,
  RecommendationStrategy,
} from '../dto/create-project.dto';

export type ProjectDocument = ProjectTemplate & Document;

@Schema()
export class ProjectTemplate {
  @Prop({ required: true, minlength: 1, maxlength: 30 })
  name: string;

  @Prop({ maxlength: 500 })
  description: string;

  @Prop({ required: true, maxlength: 500 })
  image: string;

  @Prop({ maxlength: 100 })
  web: string;

  @Prop({ required: true })
  available: boolean;

  @Prop({ type: MongooseSchema.Types.Mixed, default: {} }) // Permite cualquier tipo
  areas: any;

  @Prop({ type: [String], default: [] })
  taskTypes: string[];

  @Prop({ default: GamificationStrategy.BASIC })
  gamificationStrategy: string;

  @Prop({ default: RecommendationStrategy.SIMPLE })
  recomemendationStrategy: string;

  @Prop({
    required: true,
    type: [
      {
        name: { type: String, required: true },
        days: { type: [Number], required: true }, // Lista de números para los días (1 a 7)
        time: {
          start: { type: Number, required: true, min: 0, max: 23 }, // Hora de inicio
          end: { type: Number, required: true, min: 0, max: 23 }, // Hora de fin
        },
        startDate: { type: Date, required: true },
        endDate: { type: Date, required: true },
      },
    ],
  })
  timeIntervals: TimeInterval[];

  @Prop({ ref: 'User', required: true })
  ownerId: string;

  static collectionName() {
    return 'Projects';
  }
}

export const ProjectSchema = SchemaFactory.createForClass(ProjectTemplate);
