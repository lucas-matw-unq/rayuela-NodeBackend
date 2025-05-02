import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { TaskDocument, TaskSchemaTemplate } from './task.schema';
import { Task } from '../entities/task.entity';
import { CreateTaskDto } from '../dto/create-task.dto';
import { ProjectDao } from '../../project/persistence/project.dao';
import { TimeInterval } from '../entities/time-restriction.entity';
import { ProjectTemplate } from '../../project/persistence/project.schema';
import { Project } from '../../project/entities/project';

@Injectable()
export class TaskDao {
  constructor(
    @InjectModel(TaskSchemaTemplate.collectionName())
    private taskModel: Model<TaskDocument>,
    private projectDao: ProjectDao,
  ) {}

  async create(taskData: CreateTaskDto): Promise<TaskDocument> {
    const createdTask = new this.taskModel(taskData);
    return createdTask.save();
  }

  async getTaskById(taskId: string): Promise<Task> {
    const res = await this.taskModel.findById(taskId).exec();
    return await this.mapDocToTask(res['_doc']);
  }

  async getAllTasks(): Promise<TaskDocument[]> {
    return this.taskModel.find().exec();
  }

  async getTasksByProject(projectId: string): Promise<Task[]> {
    const tasks: TaskDocument[] = await this.taskModel
      .find({ projectId })
      .exec();
    if (!tasks) {
      throw new NotFoundException('No tasks found for this project');
    }
    const res = [];
    for (const task of tasks) {
      res.push(await this.mapDocToTask(task));
    }
    return res;
  }

  async updateTask(
    taskId: string,
    taskData: any,
  ): Promise<TaskDocument | null> {
    return this.taskModel
      .findByIdAndUpdate(taskId, taskData, { new: true })
      .exec();
  }

  async deleteTask(taskId: string): Promise<TaskDocument | null> {
    return this.taskModel.findByIdAndDelete(taskId).exec();
  }

  async findByNameOrDescription(
    name: string,
    description: string,
  ): Promise<TaskDocument | null> {
    return this.taskModel.findOne({ $or: [{ name }, { description }] }).exec();
  }

  private async mapDocToTask(doc: TaskDocument): Promise<Task> {
    const project: Project = await this.projectDao.findOne(
      doc.projectId.toString(),
    );
    const area = project.areas.features.find(
      (f) => f.properties.id?.toString() === doc.areaId?.toString(),
    );
    if (!area) {
      throw new NotFoundException('Area not found');
    }
    return new Task(
      doc._id,
      doc.name,
      doc.description,
      doc.projectId.toString(),
      this.mapTimeRestriction(doc.timeIntervalId.toString(), project),
      area,
      doc.type,
      doc.solved,
    );
  }

  private mapTimeRestriction(
    timeIntervalId: string,
    project: Project,
  ): TimeInterval {
    const ti = project.timeIntervals.find((t) => t.name === timeIntervalId);
    return new TimeInterval(
      ti.name,
      ti.days,
      ti.time,
      ti.startDate,
      ti.endDate,
    );
  }

  async deleteByProjectId(projectId: string): Promise<number> {
    const result = await this.taskModel.deleteMany({ projectId }).exec();
    return result.deletedCount;
  }

  async bulkSave(createTaskDtoList: CreateTaskDto[]): Promise<any> {
    return await this.taskModel.insertMany(createTaskDtoList);
  }

  async getRawTasksByProject(projectId: string) {
    const tasks: TaskDocument[] = await this.taskModel
      .find({ projectId })
      .exec();
    if (!tasks) {
      throw new NotFoundException('No tasks found for this project');
    }
    const res: Task[] = [];
    for (const task of tasks) {
      res.push(await this.mapDocToTask(task));
    }
    return res;
  }

  async setTaskAsSolved(id: string): Promise<TaskDocument | null> {
    const updatedTask = await this.taskModel
      .findByIdAndUpdate(id, { solved: true }, { new: true })
      .exec();

    if (!updatedTask) {
      throw new NotFoundException(`Task with id ${id} not found`);
    }

    return updatedTask;
  }
}
