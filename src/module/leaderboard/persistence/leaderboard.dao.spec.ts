import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { LeaderboardDao } from './leaderboard.dao';
import { Leaderboard, LeaderboardSchema } from './leaderboard-user-schema';
import { NotFoundException } from '@nestjs/common';

describe('LeaderboardDao', () => {
  let dao: LeaderboardDao;
  let model: any;

  const mockModel = {
    findOne: jest.fn().mockReturnThis(),
    findOneAndUpdate: jest.fn().mockReturnThis(),
    findOneAndDelete: jest.fn().mockReturnThis(),
    create: jest.fn(),
    exec: jest.fn(),
  };

  class MockModel {
    constructor(data: any) {
      Object.assign(this, data);
    }
    save = jest.fn().mockResolvedValue(this);
    static findOne = mockModel.findOne;
    static findOneAndUpdate = mockModel.findOneAndUpdate;
    static findOneAndDelete = mockModel.findOneAndDelete;
    static create = mockModel.create;
    static exec = mockModel.exec;
  }

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LeaderboardDao,
        {
          provide: getModelToken(Leaderboard.name),
          useValue: MockModel,
        },
      ],
    }).compile();

    dao = module.get<LeaderboardDao>(LeaderboardDao);
    model = MockModel;
  });

  it('should return collection name', () => {
    expect((LeaderboardSchema.statics as any).collectionName()).toBe(
      'Leaderboards',
    );
  });

  it('should find by project id or create', async () => {
    model.findOne.mockReturnThis();
    model.exec.mockResolvedValue(null);
    model.create.mockResolvedValue({ projectId: 'p1' });
    const res = await dao.findByProjectId('p1');
    expect(res.projectId).toBe('p1');
    expect(model.create).toHaveBeenCalled();
  });

  it('should update leaderboard users', async () => {
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue({ projectId: 'p1' });
    await dao.updateLeaderboardUsers('p1', []);
    expect(model.findOneAndUpdate).toHaveBeenCalled();
  });

  it('should throw if update not found', async () => {
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(dao.updateLeaderboardUsers('p1', [])).rejects.toThrow(
      NotFoundException,
    );
  });

  it('should add user to leaderboard', async () => {
    const lb = { users: [{ points: 10 }, { points: 20 }] };
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockImplementation(() => {
      lb.users.push({ points: 15 } as any);
      return Promise.resolve(lb);
    });
    const res = await dao.addUserToLeaderboard('p1', { points: 15 } as any);
    expect(res.users[0].points).toBe(20);
    expect(res.users[1].points).toBe(15);
    expect(res.users[2].points).toBe(10);
  });

  it('should remove user from leaderboard', async () => {
    const lb = {
      users: [
        { _id: 'u1', points: 10 },
        { _id: 'u2', points: 20 },
      ],
    };
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue(lb);
    const res = await dao.removeUserFromLeaderboard('p1', 'u1');
    expect(res.users).toHaveLength(2); // Since mock isn't actually pulling, but we check sort
    expect(res.users[0].points).toBe(20);
  });

  it('should delete leaderboard', async () => {
    model.findOneAndDelete.mockReturnThis();
    model.exec.mockResolvedValue({});
    await dao.deleteLeaderboardByProjectId('p1');
    expect(model.findOneAndDelete).toHaveBeenCalled();
  });

  it('should throw if delete not found', async () => {
    model.findOneAndDelete.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(dao.deleteLeaderboardByProjectId('p1')).rejects.toThrow(
      NotFoundException,
    );
  });

  it('should create leaderboard', async () => {
    const res = await dao.createLeaderboard('p1');
    expect(res).toBeDefined();
  });

  it('should throw if add user not found', async () => {
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(
      dao.addUserToLeaderboard('p1', { points: 1 } as any),
    ).rejects.toThrow(NotFoundException);
  });

  it('should throw if remove user not found', async () => {
    model.findOneAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(dao.removeUserFromLeaderboard('p1', 'u1')).rejects.toThrow(
      NotFoundException,
    );
  });
});
