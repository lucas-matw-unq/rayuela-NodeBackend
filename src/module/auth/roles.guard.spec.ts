import { Test, TestingModule } from '@nestjs/testing';
import { RolesGuard } from './roles.guard';
import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import { UserRole } from './users/user.schema';

describe('RolesGuard', () => {
    let guard: RolesGuard;
    let reflector: Reflector;

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                RolesGuard,
                {
                    provide: Reflector,
                    useValue: {
                        get: jest.fn(),
                    },
                },
            ],
        }).compile();

        guard = module.get<RolesGuard>(RolesGuard);
        reflector = module.get<Reflector>(Reflector);
    });

    it('should be defined', () => {
        expect(guard).toBeDefined();
    });

    describe('canActivate', () => {
        let context: ExecutionContext;

        beforeEach(() => {
            context = {
                getHandler: jest.fn(),
                switchToHttp: jest.fn().mockReturnValue({
                    getRequest: jest.fn(),
                }),
            } as any;
        });

        it('should return true if no roles are required', () => {
            (reflector.get as jest.Mock).mockReturnValue(null);
            expect(guard.canActivate(context)).toBe(true);
        });

        it('should return true if user has required role', () => {
            (reflector.get as jest.Mock).mockReturnValue([UserRole.Admin]);
            const request = { user: { role: UserRole.Admin } };
            (context.switchToHttp().getRequest as jest.Mock).mockReturnValue(request);
            expect(guard.canActivate(context)).toBe(true);
        });

        it('should return false if user does not have required role', () => {
            (reflector.get as jest.Mock).mockReturnValue([UserRole.Admin]);
            const request = { user: { role: UserRole.Volunteer } };
            (context.switchToHttp().getRequest as jest.Mock).mockReturnValue(request);
            expect(guard.canActivate(context)).toBe(false);
        });
    });
});
