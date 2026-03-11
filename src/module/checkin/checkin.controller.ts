import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
  Req,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { CheckinService } from './checkin.service';
import { CreateCheckinDto } from './dto/create-checkin.dto';
import { UpdateCheckinDto } from './dto/update-checkin.dto';
import { JwtAuthGuard } from '../auth/auth.guard';
import { FileInterceptor } from '@nestjs/platform-express';

@Controller('checkin')
export class CheckinController {
  constructor(private readonly checkinService: CheckinService) {}

  @UseGuards(JwtAuthGuard)
  @Post()
  @UseInterceptors(FileInterceptor('image'))
  async create(
    @Body() createCheckinDto: CreateCheckinDto,
    @Req() req: any,
    @UploadedFile() file: Express.Multer.File,
  ) {
    createCheckinDto.userId = req.user.userId;
    return this.checkinService.create({ createCheckinDto, file });
  }



  @UseGuards(JwtAuthGuard)
  @Post('/rate')
  async rate(
    @Body() rateBody: { checkinId: string; rate: number },
    @Req() req,
  ) {
    const userId = req.user.userId;
    return this.checkinService.rate({ ...rateBody, userId });
  }

  @UseGuards(JwtAuthGuard)
  @Get('user/:projectId')
  async findUserCheckins(@Req() req, @Param('projectId') projectId: string) {
    const userId = req.user.userId;
    return this.checkinService.findByProjectId(userId, projectId);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  async findAll() {
    return this.checkinService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  async findOne(@Param('id') id: string) {
    return this.checkinService.findOne(id);
  }

  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body() updateCheckinDto: UpdateCheckinDto,
  ) {
    return this.checkinService.update(id, updateCheckinDto);
  }

  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  async remove(@Param('id') id: string) {
    return this.checkinService.remove(id);
  }
}
