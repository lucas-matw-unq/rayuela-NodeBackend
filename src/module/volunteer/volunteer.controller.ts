import {
  Controller,
  Get,
  Post,
  Param,
  UseGuards,
  Request,
  Req,
} from '@nestjs/common';
import { VolunteerService } from './volunteer.service';
import { JwtAuthGuard } from '../auth/auth.guard';

@Controller('volunteer')
export class VolunteerController {
  constructor(private readonly volunteerService: VolunteerService) {}

  @UseGuards(JwtAuthGuard)
  @Post('/subscription/:id')
  subscribe(@Request() req, @Param('id') id: string) {
    return this.volunteerService.subscribeToProject(req.user, id);
  }

  @UseGuards(JwtAuthGuard)
  @Get('/projects')
  findProjects(@Req() req) {
    return this.volunteerService.findProjects(req.user.userId);
  }

  @Get('/public/projects')
  findPublicProjects() {
    return this.volunteerService.findPublicProjects();
  }
}
