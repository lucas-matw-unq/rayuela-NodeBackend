import { Test, TestingModule } from '@nestjs/testing';
import { CheckinController } from './checkin.controller';
import { CheckinService } from './checkin.service';
import { CreateCheckinDto } from './dto/create-checkin.dto';
import { UpdateCheckinDto } from './dto/update-checkin.dto';

describe('CheckinController', () => {
    let controller: CheckinController;
    let service: CheckinService;

    const mockCheckinService = {
        create: jest.fn(),
        findAll: jest.fn(),
        findOne: jest.fn(),
        update: jest.fn(),
        remove: jest.fn(),
        findByProjectId: jest.fn(),
        rate: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [CheckinController],
            providers: [
                { provide: CheckinService, useValue: mockCheckinService },
            ],
        }).compile();

        controller = module.get<CheckinController>(CheckinController);
        service = module.get<CheckinService>(CheckinService);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    describe('create', () => {
        it('should call service.create', async () => {
            const dto: CreateCheckinDto = { userId: '1', projectId: '1' } as any;
            const req = { user: { userId: '1' } };
            await controller.create(dto, req);
            expect(service.create).toHaveBeenCalled();
        });
    });

    describe('findAll', () => {
        it('should call service.findAll', async () => {
            await controller.findAll();
            expect(service.findAll).toHaveBeenCalled();
        });
    });

    describe('findOne', () => {
        it('should call service.findOne', async () => {
            await controller.findOne('1');
            expect(service.findOne).toHaveBeenCalledWith('1');
        });
    });

    describe('update', () => {
        it('should call service.update', async () => {
            const dto: UpdateCheckinDto = {};
            await controller.update('1', dto);
            expect(service.update).toHaveBeenCalledWith('1', dto);
        });
    });

    describe('remove', () => {
        it('should call service.remove', async () => {
            await controller.remove('1');
            expect(service.remove).toHaveBeenCalledWith('1');
        });
    });

    describe('findByProjectId', () => {
        it('should call service.findByProjectId', async () => {
            const req = { user: { userId: '1' } };
            await controller.findUserCheckins(req, 'proj1');
            expect(service.findByProjectId).toHaveBeenCalledWith('1', 'proj1');
        });
    });

    describe('rate', () => {
        it('should call service.rate', async () => {
            const req = { user: { userId: '1' } };
            const body = { checkinId: 'c1', rate: 5 };
            await controller.rate(body, req);
            expect(service.rate).toHaveBeenCalledWith({ ...body, userId: '1' });
        });
    });
});
