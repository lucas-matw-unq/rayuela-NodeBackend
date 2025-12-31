import checkinBuilder from './checkin.builder';
import { User } from '../auth/users/user.entity';

describe('CheckinBuilder', () => {
  it('should build a checkin with default values', () => {
    const checkin = checkinBuilder.build();
    expect(checkin.id).toBe('default-checkin-id');
  });

  it('should build a checkin with custom values', () => {
    const user = new User('t@t.com', 'u', 'p', 'T');
    const date = new Date();
    const checkin = checkinBuilder
      .withId('c1')
      .withLatitude('10')
      .withLongitude('20')
      .withDatetime(date)
      .withProjectId('p1')
      .withUser(user)
      .withTaskType('type1')
      .build();

    expect(checkin.id).toBe('c1');
    expect(checkin.latitude).toBe('10');
    expect(checkin.longitude).toBe('20');
    expect(checkin.date).toBe(date);
    expect(checkin.projectId).toBe('p1');
    expect(checkin.user).toBe(user);
    expect(checkin.taskType).toBe('type1');
  });

  it('should set related task', () => {
    const task = { getId: () => 't1' } as any;
    const checkin = checkinBuilder.withRelatedTask(task).build();
    expect(checkin.contributesTo).toBe('');
  });
});
