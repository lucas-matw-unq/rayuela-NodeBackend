import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { ProjectDao } from './project.dao';
import { ProjectTemplate } from './project.schema';
import { GamificationDao } from '../../gamification/persistence/gamification-dao.service';
import { NotFoundException } from '@nestjs/common';

describe('ProjectDao', () => {
  let dao: ProjectDao;
  let model: any;
  let gamificationDao: any;

  const mockModel = {
    find: jest.fn().mockReturnThis(),
    findById: jest.fn().mockReturnThis(),
    findByIdAndUpdate: jest.fn().mockReturnThis(),
    exec: jest.fn(),
  };

  class MockModel {
    constructor(data: any) {
      Object.assign(this, data);
    }
    save = jest.fn().mockResolvedValue(this);
    static find = mockModel.find;
    static findById = mockModel.findById;
    static findByIdAndUpdate = mockModel.findByIdAndUpdate;
    static exec = mockModel.exec;
  }

  const mockGamificationDao = {
    getGamificationByProjectId: jest.fn(),
    createNewGamificationFor: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProjectDao,
        {
          provide: getModelToken(ProjectTemplate.collectionName()),
          useValue: MockModel,
        },
        { provide: GamificationDao, useValue: mockGamificationDao },
      ],
    }).compile();

    dao = module.get<ProjectDao>(ProjectDao);
    model = MockModel;
    gamificationDao = module.get<GamificationDao>(GamificationDao);
  });

  it('should find all', async () => {
    model.find.mockReturnThis();
    model.exec.mockResolvedValue([{ name: 'P1' }]);
    const res = await dao.findAll();
    expect(res).toHaveLength(1);
  });

  it('should map time interval from db', () => {
    const ti = {
      _doc: {
        name: 'T1',
        days: [1],
        time: { start: '08:00', end: '12:00' },
        startDate: new Date(),
        endDate: new Date(),
      },
    };
    const res = dao.mapTimeIntervalFromDB(ti);
    expect(res.name).toBe('T1');
  });

  it('should throw if findOne not found', async () => {
    model.findById.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(dao.findOne('1')).rejects.toThrow(NotFoundException);
  });

  it('should find one and filter disabled areas', async () => {
    const doc = {
      name: 'P1',
      areas: {
        features: [
          { properties: { id: 'a1' } },
          { properties: { id: 'a2', disabled: true } },
        ],
      },
      taskTypes: [],
      timeIntervals: [],
      ownerId: 'o1',
    };
    model.findById.mockReturnThis();
    model.exec.mockResolvedValue(doc);
    gamificationDao.getGamificationByProjectId.mockResolvedValue({});
    jest.spyOn(dao as any, 'mapTimeIntervalFromDB').mockReturnValue({});

    const res = await dao.findOne('1');
    expect(res.areas.features).toHaveLength(1);
    expect(res.areas.features[0].properties.id).toBe('a1');
  });

  it('should update and handle new areas', async () => {
    const oldProject = {
      areas: { features: [{ properties: { id: 'old' } }] },
    };
    model.findById.mockResolvedValue(oldProject);
    model.findByIdAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue({ _id: '1' });

    const updateDto = {
      areas: {
        type: 'FeatureCollection',
        features: [{ properties: { id: 'new' } }],
      },
    };
    await dao.update('1', updateDto as any);

    expect(model.findByIdAndUpdate).toHaveBeenCalled();
    const callArgs = model.findByIdAndUpdate.mock.calls[0][1];
    expect(callArgs.$set.areas.features).toHaveLength(2);
    expect(
      callArgs.$set.areas.features.find((f) => f.properties.id === 'old')
        .properties.disabled,
    ).toBe(true);
  });

  it('should throw if update not found', async () => {
    model.findById.mockResolvedValue(null);
    await expect(dao.update('1', {})).rejects.toThrow(NotFoundException);
  });

  it('should find one', async () => {
    const doc = {
      name: 'P1',
      areas: { features: [] },
      taskTypes: [],
      timeIntervals: [],
      ownerId: 'o1',
    };
    model.findById.mockReturnThis();
    model.exec.mockResolvedValue(doc);
    gamificationDao.getGamificationByProjectId.mockResolvedValue({});

    jest.spyOn(dao, 'mapTimeIntervalFromDB').mockReturnValue({} as any);

    const res = await dao.findOne('1');
    expect(res.name).toBe('P1');
  });

  it('should create project', async () => {
    const res = await dao.create({ name: 'P1' } as any);
    expect(res).toBeDefined();
    expect(gamificationDao.createNewGamificationFor).toHaveBeenCalled();
  });

  it('should toggle available', async () => {
    const project = { available: true, name: 'P' } as any;
    jest.spyOn(dao, 'findOne').mockResolvedValue(project);
    model.findByIdAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue({});
    await dao.toggleAvailable('1');
    expect(model.findByIdAndUpdate).toHaveBeenCalled();
  });

  it('should throw if toggleAvailable not found', async () => {
    jest.spyOn(dao, 'findOne').mockResolvedValue({ available: true } as any);
    model.findByIdAndUpdate.mockReturnThis();
    model.exec.mockResolvedValue(null);
    await expect(dao.toggleAvailable('1')).rejects.toThrow(NotFoundException);
  });
});
