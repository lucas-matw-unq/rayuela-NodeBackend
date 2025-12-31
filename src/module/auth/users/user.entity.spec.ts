import { User } from './user.entity';
import { UserRole } from './user.schema';

describe('User Entity', () => {
    let user: User;

    beforeEach(() => {
        user = new User('Name', 'user', 'e@e.com', 'pass');
    });

    it('should manage account verification', () => {
        expect(user.verified).toBe(false);
        user.verifyAccount();
        expect(user.verified).toBe(true);
    });

    it('should manage projects', () => {
        user.subscribeToProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(true);
        user.unsubscribeFromProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(false);
        user.subscribeToProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(true);
    });

    it('should manage points and badges', () => {
        user.subscribeToProject('p1');
        user.addPointsFromProject(10, 'p1');
        expect(user.getGameProfileFromProject('p1').points).toBe(10);
        user.addBadgeFromProject(['badge1'], 'p1');
        expect(user.hasBadgeWithName('badge1')).toBe(true);
    });

    it('should manage ratings', () => {
        const checkin = { id: 'c1', contributesTo: 't1' } as any;
        user.addRating(checkin, 5);
        expect(user.getRatingForTaskId('t1')).toBe(5);
    });

    it('should manage contributions', () => {
        user.addContribution('t1');
        expect(user.contributions).toContain('t1');
    });

    it('should manage reset token', () => {
        user.resetToken = 'token';
        expect(user.resetToken).toBe('token');
    });

    it('should toggle project with addProject', () => {
        user.addProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(true);
        user.addProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(false);
    });

    it('should remove project', () => {
        user.addProject('p1');
        user.removeProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(false);
    });

    it('should test setters', () => {
        user.completeName = 'New';
        user.username = 'new';
        user.email = 'new@e.com';
        user.profileImage = 'new.png';
        user.verified = true;
        user.role = UserRole.Admin;
        user.checkins = [];
        user.contributions = ['t1'];

        expect(user.completeName).toBe('New');
        expect(user.username).toBe('new');
        expect(user.email).toBe('new@e.com');
        expect(user.profileImage).toBe('new.png');
        expect(user.verified).toBe(true);
        expect(user.role).toBe(UserRole.Admin);
        expect(user.checkins).toEqual([]);
        expect(user.contributions).toEqual(['t1']);
    });

    it('should unsubscribe from project', () => {
        const user = new User('N', 'u', 'e', 'p');
        user.subscribeToProject('p1');
        user.unsubscribeFromProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(false);
    });

    it('should resubscribe to project', () => {
        const user = new User('N', 'u', 'e', 'p');
        user.subscribeToProject('p1');
        user.unsubscribeFromProject('p1');
        user.subscribeToProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(true);
    });

    it('should remove project', () => {
        const user = new User('N', 'u', 'e', 'p');
        user.subscribeToProject('p1');
        user.removeProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(false);
    });

    it('should add and get ratings', () => {
        const user = new User('N', 'u', 'e', 'p');
        const checkin = { id: 'c1', contributesTo: 't1' } as any;
        user.addRating(checkin, 5);
        expect(user.getRatingForTaskId('t1')).toBe(5);
    });

    it('should handle duplicate subscription to already active project', () => {
        user.subscribeToProject('p1');
        user.subscribeToProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(true);
    });

    it('should maintain other project active state when unsubscribing', () => {
        user.subscribeToProject('p1');
        user.subscribeToProject('p2');
        user.unsubscribeFromProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(false);
        expect(user.isSubscribedToProject('p2')).toBe(true);
    });

    it('should cover branch in subscribeToProject else', () => {
        user.subscribeToProject('p1');
        user.subscribeToProject('p2');
        user.subscribeToProject('p1');
        expect(user.isSubscribedToProject('p1')).toBe(true);
        expect(user.isSubscribedToProject('p2')).toBe(true);
    });
});
