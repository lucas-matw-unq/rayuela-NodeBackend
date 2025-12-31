import { Gamification, BadgeRule, PointRule } from './gamification.entity';

describe('Gamification Entities', () => {
    describe('Gamification', () => {
        it('should create a Gamification instance', () => {
            const g = new Gamification('p1', [], []);
            expect(g.projectId).toBe('p1');
        });
    });

    describe('BadgeRule', () => {
        it('should create a BadgeRule instance', () => {
            const b = new BadgeRule('id', 'p1', 'name', 'desc', 'img', 10, true, [], 'type', 'area', 'time');
            expect(b._id).toBe('id');
            expect(b.name).toBe('name');
        });
    });

    describe('PointRule', () => {
        it('should match correctly', () => {
            const p = new PointRule('id', 'p1', 'type1', 'area1', 'time1', 10, true);
            expect(p.matchTaskType('type1')).toBe(true);
            expect(p.matchTaskType('type2')).toBe(false);
            expect(p.matchArea('area1')).toBe(true);
            expect(p.matchArea('area2')).toBe(false);
            expect(p.matchTimeInterval('time1')).toBe(true);
            expect(p.matchTimeInterval('time2')).toBe(false);
            expect(p.mustContribute).toBe(true);
        });

        it('should match ANY_KIND', () => {
            const p = new PointRule('id', 'p1', 'Cualquiera', 'Cualquiera', 'Cualquiera', 10, true);
            expect(p.matchTaskType('anything')).toBe(true);
            expect(p.matchArea('anything')).toBe(true);
            expect(p.matchTimeInterval('anything')).toBe(true);
        });

        it('should match task', () => {
            const p = new PointRule('id', 'p1', 'type1', 'area1', 'time1', 10, true);
            const task = {
                type: 'type1',
                areaGeoJSON: { properties: { id: 'area1' } },
                timeInterval: { name: 'time1' },
            } as any;
            expect(p.matchTask(task)).toBe(true);
        });
    });
});
