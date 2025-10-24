export class TimeInterval {
  name: string;
  days: number[]; // From 1(Mon) to 7(Sun)
  startDate: Date;
  endDate: Date;
  time: {
    // Between 00 and 23
    start: string; // e.g., "08:00" or "14:30:00"
    end: string;
  };

  satisfy(date: Date | string): boolean {
    const datetime = new Date(date);
    const dayOfWeek = datetime.getDay() === 0 ? 7 : datetime.getDay();

    const isValidDay = this.days.includes(dayOfWeek);

    const isValidHour = this.isValidHour(datetime);

    const isWithinDateRange =
      datetime >= new Date(this.startDate) &&
      datetime <= new Date(this.endDate);
    return isValidDay && isValidHour && isWithinDateRange;
  }

  private isValidHour(datetime: Date) {
    const [startHour, startMinute] = this.time.start.split(':').map(Number);
    const [endHour, endMinute] = this.time.end.split(':').map(Number);
    const currentHour = datetime.getHours();
    const currentMinute = datetime.getMinutes();

    return (
      (currentHour > startHour ||
        (currentHour === startHour && currentMinute >= startMinute)) &&
      (currentHour < endHour ||
        (currentHour === endHour && currentMinute < endMinute))
    );
  }

  constructor(
    name: string,
    days: number[],
    time: { start: string; end: string },
    startDate: Date,
    endDate: Date,
  ) {
    this.name = name;
    this.startDate = startDate;
    this.endDate = endDate;
    this.days = days;
    this.time = time;
  }
}
