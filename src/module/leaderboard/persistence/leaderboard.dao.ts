import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Leaderboard, LeaderboardDocument } from './leaderboard-user-schema';

@Injectable()
export class LeaderboardDao {
  constructor(
    @InjectModel(Leaderboard.name)
    private readonly leaderboardModel: Model<LeaderboardDocument>,
  ) {}

  /**
   * Obtiene el leaderboard por projectId, ordenado por puntaje.
   * @param projectId ID del proyecto.
   */
  async findByProjectId(projectId: string): Promise<Leaderboard> {
    let leaderboard = await this.leaderboardModel.findOne({ projectId }).exec();
    if (!leaderboard) {
      leaderboard = await this.leaderboardModel.create({
        projectId,
        lastUpdated: new Date(),
      });
    }
    return leaderboard;
  }

  /**
   * Crea un nuevo leaderboard para un proyecto.
   * @param projectId ID del proyecto.
   * @returns El leaderboard creado.
   */
  async createLeaderboard(projectId: string): Promise<Leaderboard> {
    const leaderboard = new this.leaderboardModel({
      projectId,
      lastUpdated: new Date(),
      users: [],
    });
    return leaderboard.save();
  }

  /**
   * Actualiza la lista de usuarios de un leaderboard y su fecha de última actualización.
   * @param projectId ID del proyecto.
   * @param users Nueva lista de usuarios.
   */
  async updateLeaderboardUsers(
    projectId: string,
    users: Leaderboard['users'],
  ): Promise<Leaderboard> {
    const leaderboard = await this.leaderboardModel
      .findOneAndUpdate(
        { projectId },
        { $set: { users, lastUpdated: new Date() } },
        { new: true },
      )
      .exec();
    if (!leaderboard) {
      throw new NotFoundException('Leaderboard not found');
    }
    return leaderboard;
  }

  /**
   * Elimina un leaderboard por projectId.
   * @param projectId ID del proyecto.
   */
  async deleteLeaderboardByProjectId(projectId: string): Promise<void> {
    const result = await this.leaderboardModel
      .findOneAndDelete({ projectId })
      .exec();
    if (!result) {
      throw new NotFoundException('Leaderboard not found');
    }
  }

  /**
   * Agrega un usuario al leaderboard de un proyecto y lo ordena por puntaje.
   * @param projectId ID del proyecto.
   * @param user Usuario a agregar.
   */
  async addUserToLeaderboard(
    projectId: string,
    user: Leaderboard['users'][number],
  ): Promise<Leaderboard> {
    const leaderboard = await this.leaderboardModel
      .findOneAndUpdate(
        { projectId },
        {
          $push: { users: user },
          $set: { lastUpdated: new Date() },
        },
        { new: true },
      )
      .exec();
    if (!leaderboard) {
      throw new NotFoundException('Leaderboard not found');
    }
    leaderboard.users.sort((a, b) => b.points - a.points);
    return leaderboard;
  }

  /**
   * Elimina un usuario del leaderboard de un proyecto y lo ordena por puntaje.
   * @param projectId ID del proyecto.
   * @param userId ID del usuario a eliminar.
   */
  async removeUserFromLeaderboard(
    projectId: string,
    userId: string,
  ): Promise<Leaderboard> {
    const leaderboard = await this.leaderboardModel
      .findOneAndUpdate(
        { projectId },
        {
          $pull: { users: { _id: userId } },
          $set: { lastUpdated: new Date() },
        },
        { new: true },
      )
      .exec();
    if (!leaderboard) {
      throw new NotFoundException('Leaderboard not found');
    }
    leaderboard.users.sort((a, b) => b.points - a.points);
    return leaderboard;
  }
}
