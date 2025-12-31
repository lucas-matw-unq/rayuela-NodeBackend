import TaskBuilder from './task.builder';

describe('TaskBuilder', () => {
  it('should build a task with custom values', () => {
    const task = TaskBuilder.withId('1')
      .withName('Name')
      .withDescription('Desc')
      .withProjectId('p1')
      .withTimeRestriction(null)
      .withArea(null)
      .withType('type1')
      .withSolved(true)
      .build();

    expect(task.getId()).toBe('1');
    expect(task.name).toBe('Name');
    expect(task.description).toBe('Desc');
    expect(task.projectId).toBe('p1');
    expect(task.type).toBe('type1');
    expect(task.solved).toBe(true);
  });
});
