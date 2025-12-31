import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { MoveDao } from './move.dao';
import { MoveTemplate } from './move.schema';
import { NotFoundException } from '@nestjs/common';

describe('MoveDao', () => {
    let dao: MoveDao;
    let model: any;

    const mockModel = {
        findByIdAndUpdate: jest.fn().mockReturnThis(),
        findByIdAndDelete: jest.fn().mockReturnThis(),
        exec: jest.fn(),
    };

    class MockModel {
        constructor(data: any) { Object.assign(this, data); }
        save = jest.fn().mockResolvedValue(this);
        static findByIdAndUpdate = mockModel.findByIdAndUpdate;
        static findByIdAndDelete = mockModel.findByIdAndDelete;
        static exec = mockModel.exec;
    }

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                MoveDao,
                {
                    provide: getModelToken(MoveTemplate.collectionName()),
                    useValue: MockModel,
                },
            ],
        }).compile();

        dao = module.get<MoveDao>(MoveDao);
        model = MockModel;
    });

    it('should create move', async () => {
        const move = {
            checkin: { id: 'c1', user: { id: 'u1' } },
            gameStatus: { newBadges: [{ name: 'B1' }] },
            score: 10,
            timestamp: new Date()
        } as any;
        const res = await dao.create(move);
        expect(res).toBe(move);
    });

    it('should update move', async () => {
        const move = { checkin: { id: 'c1', user: { id: 'u1' } }, gameStatus: { newBadges: [] } } as any;
        model.findByIdAndUpdate.mockReturnThis();
        model.exec.mockResolvedValue({});
        await dao.update('1', move);
        expect(model.findByIdAndUpdate).toHaveBeenCalled();
    });

    it('should throw if update not found', async () => {
        const move = { checkin: { id: 'c1', user: { id: 'u1' } }, gameStatus: { newBadges: [] } } as any;
        model.findByIdAndUpdate.mockReturnThis();
        model.exec.mockResolvedValue(null);
        await expect(dao.update('1', move)).rejects.toThrow(NotFoundException);
    });

    it('should remove move', async () => {
        model.findByIdAndDelete.mockReturnThis();
        model.exec.mockResolvedValue({});
        await dao.remove('1');
        expect(model.findByIdAndDelete).toHaveBeenCalledWith('1');
    });

    it('should throw if remove not found', async () => {
        model.findByIdAndDelete.mockReturnThis();
        model.exec.mockResolvedValue(null);
        await expect(dao.remove('1')).rejects.toThrow(NotFoundException);
    });
});
