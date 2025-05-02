import { User } from '../../../../auth/users/user.entity';
import { Task } from '../../../../task/entities/task.entity';

export interface IRecommendationEngine {
  generateRecommendations(
    user: User,
    completedTasksRatings: Record<string, number>,
    allTasks: Task[],
  ): { task: Task; estimatedRating: number }[];
}
