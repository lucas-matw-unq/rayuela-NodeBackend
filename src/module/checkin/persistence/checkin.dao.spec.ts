import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { CheckInDao } from './checkin.dao';
import { CheckInTemplate } from './checkin.schema';
import { NotFoundException } from '@nestjs/common';

describe('CheckInDao', () => {
  let dao: CheckInDao;
  let model: any;

  const mockModel = {
    find: jest.fn().mockReturnThis(),
    findById: jest.fn().mockReturnThis(),
    findByIdAndUpdate: jest.fn().mockReturnThis(),
    findByIdAndDelete: jest.fn().mockReturnThis(),
    exec: jest.fn(),
    sort: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    save: jest.fn(),
  };

  class MockModel {
    constructor(private data: any) {
      Object.assign(this, data);
    }
    save = jest.fn().mockResolvedValue(this);
    static find = mockModel.find;
    static findById = mockModel.findById;
    static findByIdAndUpdate = mockModel.findByIdAndUpdate;
    static findByIdAndDelete = mockModel.findByIdAndDelete;
    static sort = mockModel.sort;
    static limit = mockModel.limit;
    static exec = mockModel.exec;
  }

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        CheckInDao,
        {
          provide: getModelToken(CheckInTemplate.collectionName()),
          useValue: MockModel,
        },
      ],
    }).compile();

    dao = module.get<CheckInDao>(CheckInDao);
    model = MockModel;
  });

  it('should find all', async () => {
    model.find.mockReturnThis();
    model.exec.mockResolvedValue([]);
    const res = await dao.findAll();
    expect(res).toEqual([]);
  });

  it('should find one', async () => {
    const doc = {
      _id: '1',
      latitude: '0',
      longitude: '0',
      datetime: new Date(),
      projectId: 'p1',
      userId: 'u1',
      contributesTo: '',
      taskType: 'T',
    };
    model.findById.mockReturnThis();
    model.exec.mockResolvedValue(doc);
    const res = await dao.findOne('1');
    expect(res.projectId).toBe('p1');
  });

  it('should throw NotFound if one not found', async () => {
    model.findById.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(dao.findOne('1')).rejects.toThrow(NotFoundException);
  });

  it('should create', async () => {
    const checkin = {
      latitude: '0',
      longitude: '0',
      date: new Date(),
      projectId: 'p1',
      user: { id: 'u1' },
      contributesTo: '',
      taskType: 'T',
    } as any;
    const res = await dao.create(checkin);
    expect(res).toBeDefined();
  });

  it('should update', async () => {
    model.findByIdAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue({});
    const res = await dao.update('1', {} as any);
    expect(res).toBeDefined();
  });

  it('should throw NotFound on update if not found', async () => {
    model.findByIdAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(dao.update('1', {} as any)).rejects.toThrow(NotFoundException);
  });

  it('should remove', async () => {
    model.findByIdAndDelete.mockReturnThis();
    model.exec.mockResolvedValue({});
    await dao.remove('1');
    expect(model.findByIdAndDelete).toHaveBeenCalledWith('1');
  });

  it('should throw NotFound on remove if not found', async () => {
    model.findByIdAndDelete.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(dao.remove('1')).rejects.toThrow(NotFoundException);
  });

  it('should find by project id', async () => {
    model.find.mockReturnThis();
    model.sort.mockReturnThis();
    model.limit.mockReturnThis();
    model.exec.mockResolvedValue([]);
    await dao.findByProjectId('u1', 'p1');
    expect(model.find).toHaveBeenCalledWith({ projectId: 'p1', userId: 'u1' });
  });
});
