import { CheckinMapper } from './CheckinMapper';
import { Checkin } from '../entities/checkin.entity';
import { User } from '../../auth/users/user.entity';

describe('CheckinMapper', () => {
  const user = new User('t@t.com', 'u', 'p', 'T');
  user.id = 'user1';

  describe('toTemplate', () => {
    it('should map checkin entity to template', () => {
      const checkin = new Checkin(
        '1',
        '2',
        new Date(),
        'p1',
        user,
        'type',
        'id1',
      );
      checkin.contributesTo = 'task1';
      const template = CheckinMapper.toTemplate(checkin);
      expect(template.latitude).toBe('1');
      expect(template.longitude).toBe('2');
      expect(template.userId).toBe('user1');
      expect(template.contributesTo).toBe('task1');
    });
  });

  describe('toEntity', () => {
    it('should map template to checkin entity', () => {
      const template = {
        latitude: '1',
        longitude: '2',
        datetime: new Date(),
        projectId: 'p1',
        userId: 'user1',
        taskType: 'type',
        _id: 'id1',
        contributesTo: 'task1',
      } as any;
      const entity = CheckinMapper.toEntity(template, user);
      expect(entity.latitude).toBe('1');
      expect(entity.longitude).toBe('2');
      expect(entity.id).toBe('id1');
      expect(entity.contributesTo).toBe('task1');
    });

    it('should map template to checkin entity without contribution', () => {
      const template = {
        latitude: '1',
        longitude: '2',
        datetime: new Date(),
        projectId: 'p1',
        userId: 'user1',
        taskType: 'type',
        _id: 'id1',
      } as any;
      const entity = CheckinMapper.toEntity(template, user);
      expect(entity.contributesTo).toBe('');
    });
  });
});
