import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from './jwt.strategy';

describe('JwtStrategy', () => {
    let strategy: JwtStrategy;

    beforeEach(async () => {
        process.env.JWT_SECRET = 'test-secret';
        const module: TestingModule = await Test.createTestingModule({
            providers: [JwtStrategy],
        }).compile();

        strategy = module.get<JwtStrategy>(JwtStrategy);
    });

    it('should be defined', () => {
        expect(strategy).toBeDefined();
    });

    describe('validate', () => {
        it('should return user object from payload', async () => {
            const payload = { sub: '123', username: 'testuser', role: 'admin' };
            const result = await strategy.validate(payload as any);
            expect(result).toEqual({
                userId: '123',
                username: 'testuser',
                role: 'admin',
            });
        });
    });
});
