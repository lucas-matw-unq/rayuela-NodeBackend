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

    it('should return true for a date at the exact start time', () => {
      const validDate = new Date('2024-09-16T13:00:00'); // Lunes (día 1) a las 13:00
      expect(taskTimeRestriction.satisfy(validDate)).toBe(true);
    });

    it('should return false for a date at the exact end time', () => {
      const invalidDate = new Date('2024-09-16T19:00:00'); // Lunes (día 1) a las 19:00
      expect(taskTimeRestriction.satisfy(invalidDate)).toBe(false);
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

    it('should return false for a date outside the date range (before)', () => {
      const invalidDate = new Date('2023-12-31T15:00:00');
      expect(taskTimeRestriction.satisfy(invalidDate)).toBe(false);
    });

    it('should return false for a date outside the date range (after)', () => {
      const invalidDate = new Date('2025-01-01T15:00:00');
      expect(taskTimeRestriction.satisfy(invalidDate)).toBe(false);
    });

    it('should return false if the restriction name is "unavailable"', () => {
      taskTimeRestriction.name = 'unavailable';
      const validDate = new Date('2024-09-16T15:00:00');
      expect(taskTimeRestriction.satisfy(validDate)).toBe(false);
    });

    it('should handle Sunday correctly', () => {
      const sundayRestriction = new TimeInterval(
        '',
        [7], // Domingo
        { start: '10:00', end: '12:00' },
        new Date('2024-01-01'),
        new Date('2024-12-31'),
      );
      const sundayDate = new Date('2024-09-22T11:00:00'); // Domingo
      expect(sundayRestriction.satisfy(sundayDate)).toBe(true);
    });

    it('should handle string date inputs correctly', () => {
      const validStringDate = '2024-09-16T14:00:00'; // Lunes a las 14:00, válido
      expect(taskTimeRestriction.satisfy(validStringDate)).toBe(true); // Debería ser válido con un string
    });
  });
});
