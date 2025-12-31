import { Game, GameBuilder } from './game.entity';
import { Project } from '../../project/entities/project';

describe('Game Entity', () => {
    it('should throw error if build is missing dependencies', () => {
        const builder = new GameBuilder();
        expect(() => builder.build()).toThrow('All dependencies must be provided before building the Game instance');
    });

    it('should build game successfully', () => {
        const project = { id: 'p1' } as Project;
        const builder = new GameBuilder()
            .withProject(project)
            .withPointsEngine({} as any)
            .withBadgeEngine({} as any)
            .withLeaderboardEngine({} as any)
            .withTasks([])
            .withUsers([]);

        const game = builder.build();
        expect(game).toBeDefined();
        expect(game.project).toBe(project);

        const newUsers = [];
        game.users = newUsers;
        expect(game.users).toBe(newUsers);
    });
});
