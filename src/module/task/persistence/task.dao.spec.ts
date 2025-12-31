import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { TaskDao } from './task.dao';
import { TaskSchemaTemplate } from './task.schema';
import { ProjectDao } from '../../project/persistence/project.dao';
import { NotFoundException } from '@nestjs/common';

describe('TaskDao', () => {
    let dao: TaskDao;
    let model: any;
    let projectDao: any;

    const mockModel = {
        find: jest.fn().mockReturnThis(),
        findById: jest.fn().mockReturnThis(),
        findByIdAndUpdate: jest.fn().mockReturnThis(),
        findByIdAndDelete: jest.fn().mockReturnThis(),
        deleteMany: jest.fn().mockReturnThis(),
        findOne: jest.fn().mockReturnThis(),
        insertMany: jest.fn(),
        exec: jest.fn(),
    };

    class MockModel {
        constructor(data: any) { Object.assign(this, data); }
        save = jest.fn().mockResolvedValue(this);
        static find = mockModel.find;
        static findById = mockModel.findById;
        static findByIdAndUpdate = mockModel.findByIdAndUpdate;
        static findByIdAndDelete = mockModel.findByIdAndDelete;
        static findOne = mockModel.findOne;
        static deleteMany = mockModel.deleteMany;
        static insertMany = mockModel.insertMany;
        static exec = mockModel.exec;
    }

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                TaskDao,
                {
                    provide: getModelToken(TaskSchemaTemplate.collectionName()),
                    useValue: MockModel,
                },
                { provide: ProjectDao, useValue: mockProjectDao },
            ],
        }).compile();

        dao = module.get<TaskDao>(TaskDao);
        model = MockModel;
        projectDao = module.get<ProjectDao>(ProjectDao);
    });

    const mockProjectDao = {
        findOne: jest.fn(),
    };

    it('should get task by id', async () => {
        const doc = {
            _doc: {
                _id: '1', name: 'T1', description: 'D1', projectId: 'p1', type: 't1', solved: false, areaId: 'a1', timeIntervalId: 'i1'
            }
        };
        const project = {
            id: 'p1',
            areas: { features: [{ properties: { id: 'a1' }, geometry: {} }] },
            timeIntervals: [{ name: 'i1' }]
        };
        model.findById.mockReturnThis();
        model.exec.mockResolvedValue(doc);
        projectDao.findOne.mockResolvedValue(project);

        const res = await dao.getTaskById('1');
        expect(res.name).toBe('T1');
    });

    it('should create task', async () => {
        const dto = { name: 'T' };
        await dao.create(dto as any);
        // Constructor of MockModel was called
    });

    it('should get all tasks', async () => {
        model.find.mockReturnThis();
        model.exec.mockResolvedValue([]);
        const res = await dao.getAllTasks();
        expect(res).toEqual([]);
    });

    it('should get tasks by project', async () => {
        const docs = [{ _id: '1', projectId: 'p1', areaId: 'a1', timeIntervalId: 'i1', name: 'T1' }];
        const project = { areas: { features: [] }, timeIntervals: [] };
        model.find.mockReturnThis();
        model.exec.mockResolvedValue(docs);
        projectDao.findOne.mockResolvedValue(project);
        const res = await dao.getTasksByProject('p1');
        expect(res).toHaveLength(1);
    });

    it('should return empty if no tasks for project', async () => {
        model.find.mockReturnThis();
        model.exec.mockResolvedValue(null);
        await expect(dao.getTasksByProject('p1')).rejects.toThrow('No tasks found for this project');
    });

    it('should delete task', async () => {
        model.findByIdAndDelete.mockReturnThis();
        model.exec.mockResolvedValue({});
        await dao.deleteTask('1');
        expect(model.findByIdAndDelete).toHaveBeenCalled();
    });

    it('should find by name or description', async () => {
        model.findOne.mockReturnThis();
        model.exec.mockResolvedValue({});
        await dao.findByNameOrDescription('n', 'd');
        expect(model.findOne).toHaveBeenCalled();
    });

    it('should set task as solved', async () => {
        model.findByIdAndUpdate.mockReturnThis();
        model.exec.mockResolvedValue({});
        await dao.setTaskAsSolved('1');
        expect(model.findByIdAndUpdate).toHaveBeenCalledWith('1', { solved: true }, { new: true });
    });

    it('should throw if setting solved for missing task', async () => {
        model.findByIdAndUpdate.mockReturnThis();
        model.exec.mockResolvedValue(null);
        await expect(dao.setTaskAsSolved('1')).rejects.toThrow('Task with id 1 not found');
    });

    it('should delete by project id', async () => {
        model.deleteMany.mockReturnThis();
        model.exec.mockResolvedValue({ deletedCount: 5 });
        const res = await dao.deleteByProjectId('p1');
        expect(res).toBe(5);
    });

    it('should bulk save', async () => {
        model.insertMany.mockResolvedValue([]);
        await dao.bulkSave([]);
        expect(model.insertMany).toHaveBeenCalled();
    });

    it('should delete useless', async () => {
        const project = {
            id: 'p1',
            taskTypes: [],
            timeIntervals: [],
            areas: { features: [{ properties: { id: 'a1' } }] }
        } as any;
        model.find.mockReturnThis();
        model.exec.mockResolvedValue([]);
        model.deleteMany.mockReturnThis();
        model.exec.mockResolvedValue({});
        await dao.deleteUseless(project);
        expect(model.deleteMany).toHaveBeenCalled();
    });

    it('should update task', async () => {
        model.findByIdAndUpdate.mockReturnThis();
        model.exec.mockResolvedValue({});
        await dao.updateTask('1', {});
        expect(model.findByIdAndUpdate).toHaveBeenCalled();
    });

    it('should get raw tasks and map them', async () => {
        const docs = [{ _id: '1', projectId: 'p1', areaId: 'a1', timeIntervalId: 'i1', name: 'T1' }];
        const project = { areas: { features: [] }, timeIntervals: [] };
        model.find.mockReturnThis();
        model.exec.mockResolvedValue(docs);
        projectDao.findOne.mockResolvedValue(project);
        const res = await dao.getRawTasksByProject('p1');
        expect(res).toHaveLength(1);
    });

    it('should throw if no raw tasks found', async () => {
        model.find.mockReturnThis();
        model.exec.mockResolvedValue(null);
        await expect(dao.getRawTasksByProject('p1')).rejects.toThrow('No tasks found for this project');
    });

    it('should delete useless with missing property ids', async () => {
        const project = {
            id: 'p1',
            taskTypes: [],
            timeIntervals: [],
            areas: { features: [{ properties: { id: undefined } }, { properties: {} }] }
        } as any;
        model.find.mockReturnThis();
        model.exec.mockResolvedValue([]);
        model.deleteMany.mockReturnThis();
        model.exec.mockResolvedValue({ deletedCount: 0 });
        await dao.deleteUseless(project);
        expect(model.deleteMany).toHaveBeenCalled();
    });
});
