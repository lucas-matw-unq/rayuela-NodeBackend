import { Task } from '../../../../task/entities/task.entity';
import { User } from '../../../../auth/users/user.entity';
import { IRecommendationEngine } from './i-recommendation-engine';

export class SimpleRecommendationEngine implements IRecommendationEngine {
  generateRecommendations(
    user: User,
    completedTasksRatings: Record<string, number>,
    allTasks: Task[],
  ): { task: Task; estimatedRating: number }[] {
    return allTasks.map((task) => ({
      task,
      estimatedRating: 0,
    }));
  }
}
