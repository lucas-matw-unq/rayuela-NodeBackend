import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Injectable, NotFoundException } from '@nestjs/common';
import { ProjectDocument, ProjectTemplate } from './project.schema';
import {
  CreateProjectDto,
  Feature,
  GamificationStrategy,
  RecommendationStrategy,
} from '../dto/create-project.dto';
import { UpdateProjectDto } from '../dto/update-project.dto';
import { Project } from '../entities/project';
import { GamificationDao } from '../../gamification/persistence/gamification-dao.service';
import { Gamification } from '../../gamification/entities/gamification.entity';
import { TimeInterval } from '../../task/entities/time-restriction.entity';

@Injectable()
export class ProjectDao {
  constructor(
    @InjectModel(ProjectTemplate.collectionName())
    private readonly projectModel: Model<ProjectDocument>,
    private readonly gamificationDao: GamificationDao,
  ) {}

  async findAll(): Promise<Project[]> {
    return (await this.projectModel.find().exec()) as unknown as Project[];
  }

  mapTimeIntervalFromDB(ti: any): TimeInterval {
    const { time, name, days, startDate, endDate } = ti['_doc'];
    return new TimeInterval(name, days, time, startDate, endDate);
  }

  async findOne(id: string): Promise<Project> {
    const project = await this.projectModel.findById(id).exec();
    if (!project) {
      throw new NotFoundException('Project not found');
    }
    const gamification: Gamification =
      await this.gamificationDao.getGamificationByProjectId(id);
    return new Project(
      id,
      project.name,
      project.description,
      project.image,
      project.web,
      project.available,
      {
        ...project.areas,
        features: project.areas.features.filter((f) => !f.properties.disabled),
      },
      project.taskTypes,
      project.timeIntervals.map(this.mapTimeIntervalFromDB),
      project.ownerId,
      gamification,
      project.gamificationStrategy as GamificationStrategy,
      project.recomemendationStrategy as RecommendationStrategy,
      project.manualLocation,
    );
  }

  async create(
    createProjectDto: CreateProjectDto,
  ): Promise<ProjectTemplate & { _id: string }> {
    const project = await new this.projectModel(createProjectDto).save();
    await this.gamificationDao.createNewGamificationFor(
      project['_id']?.toString(),
    );
    return project;
  }

  async update(
    id: string,
    updateProjectDto: UpdateProjectDto,
  ): Promise<ProjectTemplate & { _id: string }> {
    const oldProject = await this.projectModel.findById(id);
    if (updateProjectDto.areas) {
      updateProjectDto.areas = {
        type: 'FeatureCollection',
        features: this.getNewFeaturesFor(
          oldProject.areas.features,
          updateProjectDto.areas.features,
        ),
      };
    }
    if (!oldProject) {
      throw new NotFoundException('Project not found');
    }
    return await this.projectModel
      .findByIdAndUpdate(id, { $set: { ...updateProjectDto } }, { new: true })
      .exec();
  }

  async toggleAvailable(id: string): Promise<void> {
    const prev = await this.findOne(id);
    const result = await this.projectModel
      .findByIdAndUpdate(id, { available: !prev.available })
      .exec();
    if (!result) {
      throw new NotFoundException('Project not found');
    }
  }

  private getNewFeaturesFor(oldFeatures: Feature[], newFeatures: Feature[]) {
    const res = [];
    for (const oldFeature of oldFeatures) {
      if (
        !newFeatures.find((f) => f.properties.id === oldFeature.properties.id) // is a new feature
      ) {
        res.push({
          // Save it disabled
          ...oldFeature,
          properties: { ...oldFeature.properties, disabled: true },
        });
      }
    }
    return res.concat(newFeatures);
  }
}
