import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { UserDao } from './user.dao';
import { UserTemplate } from './user.schema';
import { User } from './user.entity';

describe('UserDao', () => {
    let dao: UserDao;
    let model: any;

    const mockModel = {
        findOne: jest.fn().mockReturnThis(),
        findById: jest.fn().mockReturnThis(),
        findOneAndUpdate: jest.fn().mockReturnThis(),
        find: jest.fn().mockReturnThis(),
        exec: jest.fn(),
    };

    class MockModel {
        constructor(data: any) { Object.assign(this, data); }
        save = jest.fn().mockResolvedValue(this);
        static findOne = mockModel.findOne;
        static findById = mockModel.findById;
        static findOneAndUpdate = mockModel.findOneAndUpdate;
        static find = mockModel.find;
        static exec = mockModel.exec;
    }

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                UserDao,
                {
                    provide: getModelToken(UserTemplate.collectionName()),
                    useValue: MockModel,
                },
            ],
        }).compile();

        dao = module.get<UserDao>(UserDao);
        model = MockModel;
    });

    it('should find by email or username', async () => {
        model.findOne.mockReturnThis();
        model.exec.mockResolvedValue({ _id: '1', email: 'e', username: 'u', gameProfiles: [], contributions: [] });
        const res = await dao.findByEmailOrUsername('e', 'u');
        expect(res?.id).toBe('1');
    });

    it('should return null if user not found by email/username', async () => {
        model.findOne.mockReturnThis();
        model.exec.mockResolvedValue(null);
        const res = await dao.findByEmailOrUsername('e', 'u');
        expect(res).toBeNull();
    });

    it('should create user', async () => {
        const user = new User('N', 'u', 'e', 'p');
        const res = await dao.create(user);
        expect(res).toBeDefined();
    });

    it('should get user by id', async () => {
        model.findById.mockReturnThis();
        model.exec.mockResolvedValue({ _id: '1', gameProfiles: [], contributions: [] });
        const res = await dao.getUserById('1');
        expect(res?.id).toBe('1');
    });

    it('should return null if user not found by id', async () => {
        model.findById.mockReturnThis();
        model.exec.mockResolvedValue(null);
        const res = await dao.getUserById('1');
        expect(res).toBeNull();
    });

    it('should update user', async () => {
        const user = new User('N', 'u', 'e', 'p');
        const userDoc = { _id: '1', complete_name: 'N', username: 'u', email: 'e', password: 'p', gameProfiles: [], contributions: [] };
        model.findOneAndUpdate.mockReturnThis();
        model.exec.mockResolvedValue({ _doc: userDoc });
        const res = await dao.update('1', user);
        expect(res?.id).toBe('1');
    });

    it('should return null if update fails (user not found)', async () => {
        const user = new User('N', 'u', 'e', 'p');
        model.findOneAndUpdate.mockReturnThis();
        model.exec.mockResolvedValue(null);
        const res = await dao.update('1', user);
        expect(res).toBeNull();
    });

    it('should get all by project id and map results', async () => {
        model.find.mockReturnThis();
        model.exec.mockResolvedValue([{ _id: '1', gameProfiles: [], contributions: [] }]);
        const res = await dao.getAllByProjectId('p1');
        expect(res).toHaveLength(1);
        expect(res[0].id).toBe('1');
    });

    it('should get user by reset token', async () => {
        model.findOne.mockReturnThis();
        model.exec.mockResolvedValue({ _id: '1', gameProfiles: [], contributions: [] });
        const res = await dao.getUserByResetToken('token');
        expect(res.id).toBe('1');
    });
});
