import { Test, TestingModule } from '@nestjs/testing';
import { VolunteerController } from './volunteer.controller';
import { VolunteerService } from './volunteer.service';
import { JwtAuthGuard } from '../auth/auth.guard';

describe('VolunteerController', () => {
    let controller: VolunteerController;
    let service: VolunteerService;

    const mockVolunteerService = {
        subscribeToProject: jest.fn(),
        findProjects: jest.fn(),
        findPublicProjects: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [VolunteerController],
            providers: [
                { provide: VolunteerService, useValue: mockVolunteerService },
            ],
        })
            .overrideGuard(JwtAuthGuard)
            .useValue({ canActivate: () => true })
            .compile();

        controller = module.get<VolunteerController>(VolunteerController);
        service = module.get<VolunteerService>(VolunteerService);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    describe('subscribe', () => {
        it('should call service.subscribeToProject', async () => {
            const req = { user: { userId: '1' } };
            await controller.subscribe(req, 'proj1');
            expect(service.subscribeToProject).toHaveBeenCalledWith(req.user, 'proj1');
        });
    });

    describe('findProjects', () => {
        it('should call service.findProjects', async () => {
            const req = { user: { userId: '1' } };
            await controller.findProjects(req);
            expect(service.findProjects).toHaveBeenCalledWith('1');
        });
    });

    describe('findPublicProjects', () => {
        it('should call service.findPublicProjects', async () => {
            await controller.findPublicProjects();
            expect(service.findPublicProjects).toHaveBeenCalled();
        });
    });
});
