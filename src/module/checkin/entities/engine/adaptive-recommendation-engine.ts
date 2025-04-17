import { Injectable } from '@nestjs/common';
import { Task } from '../../../task/entities/task.entity';
import { User } from '../../../auth/users/user.entity';

@Injectable()
export class AdaptiveRecommendationEngine {
  private readonly k: number;
  private readonly NEUTRAL_SCORE: number;
  private RECOMMENDATIONS_LIMIT: number;
  private MAX_STARS_AMOUNT: number;

  constructor() {
    this.k = Number(process.env.K) || 5; // Valor por defecto si no se define en el entorno
    this.NEUTRAL_SCORE = Number(process.env.NEUTRAL_SCORE) || 4; // Valor por defecto si no se define en el entorno
    this.RECOMMENDATIONS_LIMIT =
      Number(process.env.RECOMMENDATIONS_LIMIT) || 10;
    this.MAX_STARS_AMOUNT = Number(process.env.MAX_STARS_AMOUNT) || 5; // Valor por defecto si no se define en el entorno
  }

  /**
   * Calcula la similitud entre dos tareas usando el coeficiente de Dice.
   * La similitud se basa en tres características clave:
   * - Área geográfica
   * - Intervalo de tiempo
   * - Tipo de tarea
   * @returns Un valor entre 0 y 1 indicando la similitud.
   */
  private calculateTaskSimilarity(task1: Task, task2: Task): number {
    const task1Attributes = new Set([
      task1.areaGeoJSON.properties.id,
      task1.timeInterval.name,
      task1.type,
    ]);
    const task2Attributes = new Set([
      task2.areaGeoJSON.properties.id,
      task2.timeInterval.name,
      task2.type,
    ]);

    const intersectionSize = [...task1Attributes].filter((attr) =>
      task2Attributes.has(attr),
    ).length;
    return (
      (2 * intersectionSize) / (task1Attributes.size + task2Attributes.size)
    );
  }

  /**
   * Obtiene las K tareas más similares a una dada, ordenadas por similitud.
   * @param targetTask - La tarea para la que se buscan tareas similares.
   * @param completedTasks - Lista de tareas completadas por el usuario.
   * @returns Lista de tareas más similares con su respectiva puntuación de similitud.
   */
  private getMostSimilarTasks(
    targetTask: Task,
    completedTasks: Task[],
  ): { task: Task; similarity: number }[] {
    return completedTasks
      .map((task) => ({
        task,
        similarity: this.calculateTaskSimilarity(targetTask, task),
      }))
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, this.k);
  }

  /**
   * Estima la valoración de una tarea en función de tareas similares y preferencias del usuario.
   * Usa una media ponderada de las valoraciones de tareas similares.
   * @param similarTasks - Lista de tareas similares con sus valores de similitud.
   * @param completedTasksRatings - Diccionario de valoraciones de tareas completadas.
   * @returns Valoración estimada entre 0 y 1.
   */
  private estimateTaskRating(
    similarTasks: { task: Task; similarity: number }[],
    completedTasksRatings: Record<string, number>,
  ): number {
    let tot = 0;
    let sumaSim = 0;
    // TODO Documentar que el resultado puede estar alterado por ese puntaje arbitrario
    //  que indica la preferencia del usuario por la realizacion de esa tarea y no otra
    for (const { task, similarity } of similarTasks) {
      let rating = completedTasksRatings[task.getId()];
      if (!rating) {
        rating = this.NEUTRAL_SCORE; // Si no hay rating, pongo un valor neutral
      } // Si no hay rating, pongo un valor no neutral definido por ENV var como 4
      tot += rating * similarity;
      sumaSim += similarity;
    }

    // Poner el 5 en env var como STARS_AMOUNT o algo asi.
    return sumaSim === 0 ? 0 : tot / sumaSim / this.MAX_STARS_AMOUNT;
  }

  /**
   * Genera recomendaciones de tareas personalizadas según las tareas completadas.
   * Filtra tareas ya completadas, encuentra las más similares y estima su valoración.
   * @param user
   * @param completedTasksRatings - Diccionario con las valoraciones de tareas completadas.
   * @param allTasks - Lista de todas las tareas disponibles.
   * @returns Lista de tareas recomendadas ordenadas por valoración estimada.
   */
  generateRecommendations(
    user: User,
    completedTasksRatings: Record<string, number>,
    allTasks: Task[],
  ): { task: Task; estimatedRating: number }[] {
    const completedTasks = allTasks.filter((task) =>
      user.contributions.includes(task.getId()),
    );
    const nonCompletedTasks = allTasks.filter((task) => !task.solved);
    return nonCompletedTasks // Excluye tareas ya completadas
      .map((task) => {
        const similarTasks = this.getMostSimilarTasks(task, completedTasks);
        return {
          task,
          estimatedRating: this.estimateTaskRating(
            similarTasks,
            completedTasksRatings,
          ),
        };
      })
      .sort((a, b) => b.estimatedRating - a.estimatedRating)
      .slice(0, this.RECOMMENDATIONS_LIMIT);
  }
}
