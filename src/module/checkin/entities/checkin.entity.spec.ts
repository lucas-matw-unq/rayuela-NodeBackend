import { Checkin } from './checkin.entity';
import { User } from '../../auth/users/user.entity';
import { Task } from '../../task/entities/task.entity';

describe('Checkin Entity', () => {
  it('should test getters and setters', () => {
    const user = new User('N', 'u', 'e', 'p');
    const date = new Date();
    const checkin = new Checkin('lat', 'long', date, 'p1', user, 'T', 'id1');

    expect(checkin.latitude).toBe('lat');
    expect(checkin.longitude).toBe('long');
    expect(checkin.date).toBe(date);
    expect(checkin.projectId).toBe('p1');
    expect(checkin.user).toBe(user);
    expect(checkin.taskType).toBe('T');
    expect(checkin.id).toBe('id1');
    expect(checkin.contributesTo).toBe('');

    const newTask = {} as Task;
    checkin.relatedTask = newTask;
    expect(checkin.relatedTask).toBe(newTask);

    const newUser = {} as User;
    checkin.user = newUser;
    expect(checkin.user).toBe(newUser);

    checkin.contributesTo = 't1';
    expect(checkin.contributesTo).toBe('t1');

    checkin.id = 'id2';
    expect(checkin.id).toBe('id2');

    const newDate = new Date();
    checkin.date = newDate;
    expect(checkin.date).toBe(newDate);

    checkin.projectId = 'p2';
    expect(checkin.projectId).toBe('p2');

    checkin.validateContribution('t2');
    expect(checkin.contributesTo).toBe('t2');
  });

  it('should create from DTO', () => {
    const dto = {
      latitude: 'lat',
      longitude: 'long',
      datetime: new Date(),
      projectId: 'p1',
      taskType: 'T',
    };
    const user = {} as User;
    const checkin = Checkin.fromDTO(dto as any, user);
    expect(checkin.latitude).toBe('lat');
  });
});
