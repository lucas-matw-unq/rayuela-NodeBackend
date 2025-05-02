import { TimeInterval } from '../../task/entities/time-restriction.entity';

export enum GamificationStrategy {
  BASIC = 'SIN ADAPTACION',
  ELASTIC = 'ELASTICA',
}

export enum RecommendationStrategy {
  SIMPLE = 'SIMPLE',
  ADAPTIVE = 'ADAPTIVE',
}

export class CreateProjectDto {
  name: string;
  description?: string;
  image: string;
  web?: string;
  available: boolean;
  areas: FeatureCollection;
  taskTypes: string[];
  timeIntervals: TimeInterval[];
  ownerId: string;
  gamificationStrategy?: GamificationStrategy = GamificationStrategy.BASIC;
}

export interface FeatureCollection {
  type: 'FeatureCollection';
  features: Feature[];
}

export interface Feature {
  type: string;
  properties: Record<string, any> & { id: string | number };
  geometry: {
    type: string;
    coordinates: number[][][];
  };
}
