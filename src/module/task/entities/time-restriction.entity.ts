export class TimeInterval {
  name: string;
  days: number[]; // From 1(Mon) to 7(Sun)
  startDate: Date;
  endDate: Date;
  time: {
    // Between 00 and 23
    start: number;
    end: number;
  };

  satisfy(date: Date | string): boolean {
    const datetime = new Date(date);
    const dayOfWeek = datetime.getDay() === 0 ? 7 : datetime.getDay();

    const hour = datetime.getHours();

    const isValidDay = this.days.includes(dayOfWeek);
    const isValidHour = hour >= this.time.start && hour < this.time.end;

    const isWithinDateRange =
      !this.endDate || (datetime >= this.startDate && datetime <= this.endDate);
    return isValidDay && isValidHour && isWithinDateRange;
  }

  constructor(
    name: string,
    days: number[],
    time: { start: number; end: number },
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
