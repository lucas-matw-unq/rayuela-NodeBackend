import { UserMapper } from './UserMapper';
import { User } from './user.entity';
import { UserRole } from './user.schema';

describe('UserMapper', () => {
  it('should map document to entity', () => {
    const doc = {
      complete_name: 'Name',
      username: 'user',
      email: 'e@e.com',
      password: 'p',
      profile_image: 'img',
      verified: true,
      role: UserRole.Volunteer,
      _id: '1',
      gameProfiles: [],
      contributions: [],
    } as any;
    const entity = UserMapper.toEntity(doc);
    expect(entity.id).toBe('1');
    expect(entity.completeName).toBe('Name');
  });

  it('should map entity to template', () => {
    const entity = new User('Name', 'user', 'e@e.com', 'p');
    entity.id = '1';
    const template = UserMapper.toTemplate(entity);
    expect(template.complete_name).toBe('Name');
    expect(template.username).toBe('user');
  });

  it('should map entity to template with ratings', () => {
    const entity = new User('Name', 'user', 'e@e.com', 'p');
    entity.id = '1';
    entity.addRating({ id: 'c1', contributesTo: 't1' } as any, 5);
    const template = UserMapper.toTemplate(entity);
    expect(template.complete_name).toBe('Name');
    expect(template.ratings).toHaveLength(1);
    expect(template.ratings[0].score).toBe(5);
  });
});
