import { TimeInterval } from './time-restriction.entity';

describe('TaskTimeRestriction', () => {
  let taskTimeRestriction: TimeInterval;

  beforeEach(() => {
    taskTimeRestriction = new TimeInterval(
      '',
      [1, 3, 5],
      {
        start: '13:00:00',
        end: '19:00:00',
      },
      new Date('01/01/2024'),
      new Date('12/31/2024'),
    ); // Lunes, Miércoles y Viernes de 13 a 19
  });

  it('should initialize with correct values', () => {
    expect(taskTimeRestriction.days).toEqual([1, 3, 5]); // Días Lunes, Miércoles y Viernes
    expect(taskTimeRestriction.time.start).toBe('13:00:00'); // Hora de inicio 13
    expect(taskTimeRestriction.time.end).toBe('19:00:00'); // Hora de fin 19
  });

  describe('satisfy method', () => {
    it('should return true for valid day and time within the restriction', () => {
      const validDate = new Date('2024-09-16T15:00:00'); // Lunes (día 1) a las 15:00
      expect(taskTimeRestriction.satisfy(validDate)).toBe(true); // Debería ser válido
    });

    it('should return false for invalid day', () => {
      const invalidDate = new Date('2024-09-17T15:00:00'); // Martes (día 2) a las 15:00
      expect(taskTimeRestriction.satisfy(invalidDate)).toBe(false); // Día no permitido
    });

    it('should return false for valid day but outside the time range', () => {
      const invalidTime = new Date('2024-09-16T20:00:00'); // Lunes (día 1) a las 20:00, fuera del rango de 13-19
      expect(taskTimeRestriction.satisfy(invalidTime)).toBe(false); // Hora fuera del rango
    });

    it('should return false for both invalid day and time', () => {
      const invalidDayAndTime = new Date('2024-09-17T20:00:00'); // Martes (día 2) a las 20:00
      expect(taskTimeRestriction.satisfy(invalidDayAndTime)).toBe(false); // Ni el día ni la hora son válidos
    });

    it('should handle string date inputs correctly', () => {
      const validStringDate = '2024-09-16T14:00:00'; // Lunes a las 14:00, válido
      expect(taskTimeRestriction.satisfy(validStringDate)).toBe(true); // Debería ser válido con un string
    });
  });
});
