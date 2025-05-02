import { Module } from '@nestjs/common';
import { CheckinService } from './checkin.service';
import { CheckinController } from './checkin.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from '../auth/auth.module';
import { CheckInSchema, CheckInTemplate } from './persistence/checkin.schema';
import { CheckInDao } from './persistence/checkin.dao';
import { TaskModule } from '../task/task.module';
import { ProjectModule } from '../project/project.module';
import { MoveSchema, MoveTemplate } from './persistence/move.schema';
import { MoveDao } from './persistence/move.dao';
import { GamificationModule } from '../gamification/gamification.module';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: CheckInTemplate.collectionName(), schema: CheckInSchema },
      { name: MoveTemplate.collectionName(), schema: MoveSchema },
    ]),
    AuthModule,
    TaskModule,
    ProjectModule,
    GamificationModule,
  ],
  exports: [CheckinService],
  controllers: [CheckinController],
  providers: [CheckinService, CheckInDao, MoveDao],
})
export class CheckinModule {}
