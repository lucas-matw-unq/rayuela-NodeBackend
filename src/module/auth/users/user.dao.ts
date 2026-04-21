import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { UserDocument, UserTemplate } from './user.schema';
import { User } from './user.entity';
import { UserMapper } from './UserMapper';

@Injectable()
export class UserDao implements OnModuleInit {
  private readonly logger = new Logger(UserDao.name);

  constructor(
    @InjectModel(UserTemplate.collectionName())
    private userModel: Model<UserDocument>,
  ) {}

  async onModuleInit() {
    await this.ensureGoogleIdIndex();
  }

  async findByEmailOrUsername(
    email: string,
    username: string,
  ): Promise<User | null> {
    const userDocument = await this.userModel
      .findOne({ $or: [{ email }, { username }] })
      .exec();
    return userDocument ? UserMapper.toEntity(userDocument) : null;
  }

  async findByGoogleId(googleId: string): Promise<User | null> {
    const userDocument = await this.userModel.findOne({ googleId }).exec();
    return userDocument ? UserMapper.toEntity(userDocument) : null;
  }

  async create(userData: User): Promise<User> {
    const createdUser = new this.userModel(UserMapper.toTemplate(userData));
    const savedUser = await createdUser.save();
    return UserMapper.toEntity(savedUser);
  }

  async getUserById(userId: string): Promise<User | null> {
    const userDocument = await this.userModel.findById(userId).exec();
    return userDocument ? UserMapper.toEntity(userDocument) : null;
  }

  async update(id: string, userData: User): Promise<User | null> {
    const updatedUser = await this.userModel
      .findOneAndUpdate({ _id: id }, UserMapper.toTemplate(userData), {
        new: true,
      })
      .exec();
    return updatedUser ? UserMapper.toEntity(updatedUser['_doc']) : null;
  }

  async getAllByProjectId(projectId: string): Promise<User[]> {
    const userDocuments = await this.userModel
      .find({
        gameProfiles: {
          $elemMatch: { projectId: projectId },
        },
      })
      .exec();

    return userDocuments.map((doc) => UserMapper.toEntity(doc));
  }

  async getUserByResetToken(token: string) {
    const u = await this.userModel.findOne({ resetToken: token }).exec();
    return u ? UserMapper.toEntity(u) : null;
  }

  private async ensureGoogleIdIndex() {
    const expectedPartialFilterExpression = {
      googleId: { $exists: true, $type: 'string' },
    };

    try {
      const indexes = await this.userModel.collection.indexes();
      const googleIdIndex = indexes.find((index) => index.name === 'googleId_1');
      const hasExpectedIndex =
        googleIdIndex?.unique === true &&
        JSON.stringify(googleIdIndex.partialFilterExpression || {}) ===
          JSON.stringify(expectedPartialFilterExpression);

      if (googleIdIndex && !hasExpectedIndex) {
        await this.userModel.collection.dropIndex('googleId_1');
      }

      if (!hasExpectedIndex) {
        await this.userModel.collection.createIndex(
          { googleId: 1 },
          {
            unique: true,
            partialFilterExpression: expectedPartialFilterExpression,
            name: 'googleId_1',
          },
        );
      }
    } catch (error) {
      this.logger.warn(
        `Could not ensure googleId index: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}
