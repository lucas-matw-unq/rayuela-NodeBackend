import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  UseGuards,
  Patch,
  Req,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/auth.guard';
import { UserRole } from '../auth/users/user.schema';
import { Roles } from '../auth/role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { CreateProjectDto } from './dto/create-project.dto';
import { ProjectService } from './project.service';
import { UserService } from '../auth/users/user.service';
import { TimeInterval } from '../task/entities/time-restriction.entity';
import { UpdateProjectDto } from './dto/update-project.dto';

@Controller('projects')
export class ProjectController {
  constructor(
    private readonly projectService: ProjectService,
    private readonly userService: UserService,
  ) {}

  @Get('/task-combinations/:id')
  getTaskCombination(@Param('id') id: string) {
    return this.projectService.getTaskCombinations(id);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.projectService.findAll();
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.Admin)
  @Post()
  create(@Body() createProjectDto: CreateProjectDto) {
    return this.projectService.create(createProjectDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string, @Req() req) {
    const userId = req.user.userId;
    return this.projectService.findOne(id, userId);
  }

  @Get('public/:id')
  findOnePublic(@Param('id') id: string) {
    return this.projectService.findOnePublic(id);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.Admin)
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateProjectDto: UpdateProjectDto) {
    return this.projectService.update(id, updateProjectDto);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(UserRole.Admin)
  @Post('/availability/:id')
  toggleAvailable(@Param('id') id: string) {
    return this.projectService.toggleAvailable(id);
  }

  @Post('init')
  init() {
    const projects: CreateProjectDto[] = [
      {
        name: 'Anticipando la crecida',
        ownerId: '66e9ec13b985ec9c2d0fd9db',
        timeIntervals: [
          {
            name: 'a la tarde',
            startDate: new Date(),
            endDate: new Date('01/01/2026'),
            days: [1, 2, 3, 4, 5],
            time: {
              start: 0,
              end: 19,
            },
          } as TimeInterval,
          {
            name: 'finde morning',
            startDate: new Date(),
            endDate: new Date('01/01/2026'),
            days: [6, 7],
            time: {
              start: 0,
              end: 11,
            },
          } as TimeInterval,
        ],
        description:
          'Estrategias comunitarias para la reducción de desastres e inundaciones urbanas. Contribuir en la reducción de riesgos ante desastres asociados a eventos hidro-meteorológicos, mediante el diálogo con actores territoriales con el fin de fortalecer el sistema de alerta temprana comunitario centrado en la población.',
        image:
          'https://img.freepik.com/vector-gratis/paisaje-lago-diseno-plano_52683-76609.jpg',
        web: 'https://www.unq.edu.ar/',
        available: true,
        manualLocation: true,
        areas: {
          type: 'FeatureCollection',
          features: [
            {
              type: 'Feature',
              properties: {
                cid: '0',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 1,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72499997199998, -36.65485191799996],
                    [-69.7251911063333, -36.65485984966663],
                    [-69.72517993255157, -36.65512911127481],
                    [-69.72498879821825, -36.655121179608145],
                    [-69.72499997199998, -36.65485191799996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '1',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 2,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7251911063333, -36.65485984966663],
                    [-69.72538224066663, -36.6548677813333],
                    [-69.7253710668849, -36.65513704294148],
                    [-69.72517993255157, -36.65512911127481],
                    [-69.7251911063333, -36.65485984966663],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '2',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 3,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72538224066663, -36.6548677813333],
                    [-69.72557337499995, -36.65487571299997],
                    [-69.725525177603, -36.655138175770055],
                    [-69.7253710668849, -36.65513704294148],
                    [-69.72538224066663, -36.6548677813333],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '3',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 4,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72571614249995, -36.65492330199996],
                    [-69.72563092148776, -36.65517896593195],
                    [-69.725525177603, -36.655138175770055],
                    [-69.72557337499995, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '4',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 5,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72571614249995, -36.65492330199996],
                    [-69.72585890999994, -36.65497089099995],
                    [-69.7258550186, -36.65522778689421],
                    [-69.72563092148776, -36.65517896593195],
                    [-69.72571614249995, -36.65492330199996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '5',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 6,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72603736949995, -36.65491735324996],
                    [-69.72611480771225, -36.65517548110648],
                    [-69.7258550186, -36.65522778689421],
                    [-69.72585890999994, -36.65497089099995],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '6',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 7,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72603736949995, -36.65491735324996],
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72629326721226, -36.65512194335649],
                    [-69.72611480771225, -36.65517548110648],
                    [-69.72603736949995, -36.65491735324996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '7',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 8,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72639428849996, -36.654810277749974],
                    [-69.72647172671226, -36.6550684056065],
                    [-69.72629326721226, -36.65512194335649],
                    [-69.72621582899995, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '8',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 9,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72639428849996, -36.654810277749974],
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72661146710612, -36.65502055060449],
                    [-69.72647172671226, -36.6550684056065],
                    [-69.72639428849996, -36.654810277749974],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '9',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 10,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72677103666662, -36.65475673999998],
                    [-69.72677103666662, -36.65502623335248],
                    [-69.72661146710612, -36.65502055060449],
                    [-69.72657274799997, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '10',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 11,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72677103666662, -36.65475673999998],
                    [-69.72696932533329, -36.65475673999998],
                    [-69.72696932533329, -36.65502623335248],
                    [-69.72677103666662, -36.65502623335248],
                    [-69.72677103666662, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '11',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 12,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72696932533329, -36.65475673999998],
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72719906031293, -36.6550225126132],
                    [-69.72696932533329, -36.65502623335248],
                    [-69.72696932533329, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '12',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 13,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72736590233329, -36.65470915066663],
                    [-69.72742879495927, -36.65497120254058],
                    [-69.72719906031293, -36.6550225126132],
                    [-69.72716761399994, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '13',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 14,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72736590233329, -36.65470915066663],
                    [-69.72756419066663, -36.654661561333285],
                    [-69.7276270832926, -36.65492361320723],
                    [-69.72742879495927, -36.65497120254058],
                    [-69.72736590233329, -36.65470915066663],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '14',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 15,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72756419066663, -36.654661561333285],
                    [-69.72776247899998, -36.654613971999936],
                    [-69.7277438816084, -36.65487010706685],
                    [-69.7276270832926, -36.65492361320723],
                    [-69.72756419066663, -36.654661561333285],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '15',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 16,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72776247899998, -36.654613971999936],
                    [-69.72792110966664, -36.65467742433327],
                    [-69.72782102225753, -36.65492764259315],
                    [-69.7277438816084, -36.65487010706685],
                    [-69.72776247899998, -36.654613971999936],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '16',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 17,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72792110966664, -36.65467742433327],
                    [-69.72807974033331, -36.65474087666661],
                    [-69.7279796529242, -36.65499109492649],
                    [-69.72782102225753, -36.65492764259315],
                    [-69.72792110966664, -36.65467742433327],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '17',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 18,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72807974033331, -36.65474087666661],
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72816009392011, -36.65506119374942],
                    [-69.7279796529242, -36.65499109492649],
                    [-69.72807974033331, -36.65474087666661],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '18',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 19,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72840493349997, -36.654840020999956],
                    [-69.72834846674937, -36.655103532239025],
                    [-69.72816009392011, -36.65506119374942],
                    [-69.72823837099997, -36.654804328999944],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '19',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 20,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72840493349997, -36.654840020999956],
                    [-69.72857149599997, -36.65487571299997],
                    [-69.7285320727947, -36.65514174987086],
                    [-69.72834846674937, -36.655103532239025],
                    [-69.72840493349997, -36.654840020999956],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '20',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 21,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72857149599997, -36.65487571299997],
                    [-69.72871426349997, -36.654887609999975],
                    [-69.72869188384006, -36.655156172502686],
                    [-69.7285320727947, -36.65514174987086],
                    [-69.72857149599997, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '21',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 22,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72871426349997, -36.654887609999975],
                    [-69.72885703099996, -36.65489950699998],
                    [-69.72883465134005, -36.65516806950269],
                    [-69.72869188384006, -36.655156172502686],
                    [-69.72871426349997, -36.654887609999975],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '0',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 23,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72499997199998, -36.65485191799996],
                    [-69.72528667349997, -36.654863815499965],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72500369659389, -36.65476216413057],
                    [-69.72499997199998, -36.65485191799996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '1',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 24,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72500369659389, -36.65476216413057],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72529412268779, -36.65468430776117],
                    [-69.7250074211878, -36.65467241026117],
                    [-69.72500369659389, -36.65476216413057],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '2',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 25,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72528667349997, -36.654863815499965],
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72528667349997, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '3',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 26,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72560550659793, -36.65470073781991],
                    [-69.72529412268779, -36.65468430776117],
                    [-69.72529039809388, -36.65477406163057],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '4',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 27,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72557337499995, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '5',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 28,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72586150426658, -36.654799627070446],
                    [-69.72560550659793, -36.65470073781991],
                    [-69.72558944079894, -36.65478822540994],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '6',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 29,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72585890999994, -36.65497089099995],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '7',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 30,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72616420352509, -36.65469173026228],
                    [-69.72586150426658, -36.654799627070446],
                    [-69.72586020713325, -36.6548852590352],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '8',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 31,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72621582899995, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '9',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 32,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72654693526253, -36.65458086626364],
                    [-69.72616420352509, -36.65469173026228],
                    [-69.72619001626252, -36.65477777288112],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '10',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 33,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72687018099995, -36.65475673999998],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72657274799997, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '11',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 34,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72687018099995, -36.65457707776498],
                    [-69.72654693526253, -36.65458086626364],
                    [-69.72655984163126, -36.65466880313181],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '12',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 35,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72687018099995, -36.65475673999998],
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72687018099995, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '13',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 36,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72714664979128, -36.654579558257836],
                    [-69.72687018099995, -36.65457707776498],
                    [-69.72687018099995, -36.65466690888248],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '14',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 37,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72746504649996, -36.65468535599996],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72716761399994, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '15',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 38,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72715713189561, -36.65466814912891],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72742311808264, -36.65451065475066],
                    [-69.72714664979128, -36.654579558257836],
                    [-69.72715713189561, -36.65466814912891],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '16',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 39,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72746504649996, -36.65468535599996],
                    [-69.72776247899998, -36.654613971999936],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72746504649996, -36.65468535599996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '17',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 40,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7274440822913, -36.654598005375306],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72777487726103, -36.65444321528866],
                    [-69.72742311808264, -36.65451065475066],
                    [-69.7274440822913, -36.654598005375306],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '18',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 41,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72776247899998, -36.654613971999936],
                    [-69.72800042499998, -36.65470915049994],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72776247899998, -36.654613971999936],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '19',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 42,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72806714993939, -36.654542338326685],
                    [-69.72777487726103, -36.65444321528866],
                    [-69.7277686781305, -36.654528593644294],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '20',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 43,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72800042499998, -36.65470915049994],
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72800042499998, -36.65470915049994],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '21',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 44,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.7282905557199, -36.65463308583362],
                    [-69.72806714993939, -36.654542338326685],
                    [-69.72803378746968, -36.65462574441331],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '22',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 45,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72857149599997, -36.65487571299997],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.72823837099997, -36.654804328999944],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '23',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 46,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72826446335993, -36.654718707416784],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72859777813682, -36.65469835508604],
                    [-69.7282905557199, -36.65463308583362],
                    [-69.72826446335993, -36.654718707416784],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '24',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 47,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72857149599997, -36.65487571299997],
                    [-69.72885703099996, -36.65489950699998],
                    [-69.7288644908866, -36.654809986165745],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72857149599997, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '25',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 48,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7285846370684, -36.654787034043004],
                    [-69.7288644908866, -36.654809986165745],
                    [-69.72887195077324, -36.65472046533151],
                    [-69.72859777813682, -36.65469835508604],
                    [-69.7285846370684, -36.654787034043004],
                  ],
                ],
              },
            },
          ],
        },
        taskTypes: ['Sacar fotos', 'Llenar formularios'],
      },
      {
        name: 'Cyano',
        ownerId: '66e9ec13b985ec9c2d0fd9db',
        timeIntervals: [
          {
            name: 'a la tarde',
            startDate: new Date(),
            endDate: new Date('01/01/2026'),
            days: [1, 2, 3, 4, 5],
            time: {
              start: 0,
              end: 19,
            },
          } as TimeInterval,
          {
            name: 'finde morning',
            startDate: new Date(),
            endDate: new Date('01/01/2026'),
            days: [6, 7],
            time: {
              start: 0,
              end: 11,
            },
          } as TimeInterval,
        ],
        description:
          'Eutrofización de cuerpos de agua y cianobacterias.Se aborda la eutrofización de cuerpos de agua superficiales de manera interrelacionada con su cuenca de aporte, los diferentes usos del agua y el Cianosemáforo, para la prevención del riesgo en aguas de uso recreativo',
        image:
          'https://img.freepik.com/vector-gratis/paisaje-lago-diseno-plano_52683-76609.jpg',
        web: 'https://www.unq.edu.ar/',
        available: true,
        manualLocation: true,
        areas: {
          type: 'FeatureCollection',
          features: [
            {
              type: 'Feature',
              properties: {
                cid: '0',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 1,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72499997199998, -36.65485191799996],
                    [-69.7251911063333, -36.65485984966663],
                    [-69.72517993255157, -36.65512911127481],
                    [-69.72498879821825, -36.655121179608145],
                    [-69.72499997199998, -36.65485191799996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '1',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 2,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7251911063333, -36.65485984966663],
                    [-69.72538224066663, -36.6548677813333],
                    [-69.7253710668849, -36.65513704294148],
                    [-69.72517993255157, -36.65512911127481],
                    [-69.7251911063333, -36.65485984966663],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '2',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 3,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72538224066663, -36.6548677813333],
                    [-69.72557337499995, -36.65487571299997],
                    [-69.725525177603, -36.655138175770055],
                    [-69.7253710668849, -36.65513704294148],
                    [-69.72538224066663, -36.6548677813333],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '3',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 4,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72571614249995, -36.65492330199996],
                    [-69.72563092148776, -36.65517896593195],
                    [-69.725525177603, -36.655138175770055],
                    [-69.72557337499995, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '4',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 5,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72571614249995, -36.65492330199996],
                    [-69.72585890999994, -36.65497089099995],
                    [-69.7258550186, -36.65522778689421],
                    [-69.72563092148776, -36.65517896593195],
                    [-69.72571614249995, -36.65492330199996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '5',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 6,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72603736949995, -36.65491735324996],
                    [-69.72611480771225, -36.65517548110648],
                    [-69.7258550186, -36.65522778689421],
                    [-69.72585890999994, -36.65497089099995],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '6',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 7,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72603736949995, -36.65491735324996],
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72629326721226, -36.65512194335649],
                    [-69.72611480771225, -36.65517548110648],
                    [-69.72603736949995, -36.65491735324996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '7',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 8,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72639428849996, -36.654810277749974],
                    [-69.72647172671226, -36.6550684056065],
                    [-69.72629326721226, -36.65512194335649],
                    [-69.72621582899995, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '8',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 9,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72639428849996, -36.654810277749974],
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72661146710612, -36.65502055060449],
                    [-69.72647172671226, -36.6550684056065],
                    [-69.72639428849996, -36.654810277749974],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '9',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 10,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72677103666662, -36.65475673999998],
                    [-69.72677103666662, -36.65502623335248],
                    [-69.72661146710612, -36.65502055060449],
                    [-69.72657274799997, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '10',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 11,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72677103666662, -36.65475673999998],
                    [-69.72696932533329, -36.65475673999998],
                    [-69.72696932533329, -36.65502623335248],
                    [-69.72677103666662, -36.65502623335248],
                    [-69.72677103666662, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '11',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 12,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72696932533329, -36.65475673999998],
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72719906031293, -36.6550225126132],
                    [-69.72696932533329, -36.65502623335248],
                    [-69.72696932533329, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '12',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 13,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72736590233329, -36.65470915066663],
                    [-69.72742879495927, -36.65497120254058],
                    [-69.72719906031293, -36.6550225126132],
                    [-69.72716761399994, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '13',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 14,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72736590233329, -36.65470915066663],
                    [-69.72756419066663, -36.654661561333285],
                    [-69.7276270832926, -36.65492361320723],
                    [-69.72742879495927, -36.65497120254058],
                    [-69.72736590233329, -36.65470915066663],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '14',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 15,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72756419066663, -36.654661561333285],
                    [-69.72776247899998, -36.654613971999936],
                    [-69.7277438816084, -36.65487010706685],
                    [-69.7276270832926, -36.65492361320723],
                    [-69.72756419066663, -36.654661561333285],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '15',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 16,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72776247899998, -36.654613971999936],
                    [-69.72792110966664, -36.65467742433327],
                    [-69.72782102225753, -36.65492764259315],
                    [-69.7277438816084, -36.65487010706685],
                    [-69.72776247899998, -36.654613971999936],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '16',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 17,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72792110966664, -36.65467742433327],
                    [-69.72807974033331, -36.65474087666661],
                    [-69.7279796529242, -36.65499109492649],
                    [-69.72782102225753, -36.65492764259315],
                    [-69.72792110966664, -36.65467742433327],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '17',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 18,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72807974033331, -36.65474087666661],
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72816009392011, -36.65506119374942],
                    [-69.7279796529242, -36.65499109492649],
                    [-69.72807974033331, -36.65474087666661],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '18',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 19,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72840493349997, -36.654840020999956],
                    [-69.72834846674937, -36.655103532239025],
                    [-69.72816009392011, -36.65506119374942],
                    [-69.72823837099997, -36.654804328999944],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '19',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 20,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72840493349997, -36.654840020999956],
                    [-69.72857149599997, -36.65487571299997],
                    [-69.7285320727947, -36.65514174987086],
                    [-69.72834846674937, -36.655103532239025],
                    [-69.72840493349997, -36.654840020999956],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '20',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 21,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72857149599997, -36.65487571299997],
                    [-69.72871426349997, -36.654887609999975],
                    [-69.72869188384006, -36.655156172502686],
                    [-69.7285320727947, -36.65514174987086],
                    [-69.72857149599997, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '21',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 22,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72871426349997, -36.654887609999975],
                    [-69.72885703099996, -36.65489950699998],
                    [-69.72883465134005, -36.65516806950269],
                    [-69.72869188384006, -36.655156172502686],
                    [-69.72871426349997, -36.654887609999975],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '0',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 23,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72499997199998, -36.65485191799996],
                    [-69.72528667349997, -36.654863815499965],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72500369659389, -36.65476216413057],
                    [-69.72499997199998, -36.65485191799996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '1',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 24,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72500369659389, -36.65476216413057],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72529412268779, -36.65468430776117],
                    [-69.7250074211878, -36.65467241026117],
                    [-69.72500369659389, -36.65476216413057],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '2',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 25,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72528667349997, -36.654863815499965],
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72528667349997, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '3',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 26,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72560550659793, -36.65470073781991],
                    [-69.72529412268779, -36.65468430776117],
                    [-69.72529039809388, -36.65477406163057],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '4',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 27,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72557337499995, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '5',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 28,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72586150426658, -36.654799627070446],
                    [-69.72560550659793, -36.65470073781991],
                    [-69.72558944079894, -36.65478822540994],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '6',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 29,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72585890999994, -36.65497089099995],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '7',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 30,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72616420352509, -36.65469173026228],
                    [-69.72586150426658, -36.654799627070446],
                    [-69.72586020713325, -36.6548852590352],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '8',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 31,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72621582899995, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '9',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 32,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72654693526253, -36.65458086626364],
                    [-69.72616420352509, -36.65469173026228],
                    [-69.72619001626252, -36.65477777288112],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '10',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 33,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72687018099995, -36.65475673999998],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72657274799997, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '11',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 34,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72687018099995, -36.65457707776498],
                    [-69.72654693526253, -36.65458086626364],
                    [-69.72655984163126, -36.65466880313181],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '12',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 35,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72687018099995, -36.65475673999998],
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72687018099995, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '13',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 36,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72714664979128, -36.654579558257836],
                    [-69.72687018099995, -36.65457707776498],
                    [-69.72687018099995, -36.65466690888248],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '14',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 37,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72746504649996, -36.65468535599996],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72716761399994, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '15',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 38,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72715713189561, -36.65466814912891],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72742311808264, -36.65451065475066],
                    [-69.72714664979128, -36.654579558257836],
                    [-69.72715713189561, -36.65466814912891],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '16',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 39,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72746504649996, -36.65468535599996],
                    [-69.72776247899998, -36.654613971999936],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72746504649996, -36.65468535599996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '17',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 40,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7274440822913, -36.654598005375306],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72777487726103, -36.65444321528866],
                    [-69.72742311808264, -36.65451065475066],
                    [-69.7274440822913, -36.654598005375306],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '18',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 41,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72776247899998, -36.654613971999936],
                    [-69.72800042499998, -36.65470915049994],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72776247899998, -36.654613971999936],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '19',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 42,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72806714993939, -36.654542338326685],
                    [-69.72777487726103, -36.65444321528866],
                    [-69.7277686781305, -36.654528593644294],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '20',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 43,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72800042499998, -36.65470915049994],
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72800042499998, -36.65470915049994],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '21',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 44,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.7282905557199, -36.65463308583362],
                    [-69.72806714993939, -36.654542338326685],
                    [-69.72803378746968, -36.65462574441331],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '22',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 45,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72857149599997, -36.65487571299997],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.72823837099997, -36.654804328999944],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '23',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 46,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72826446335993, -36.654718707416784],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72859777813682, -36.65469835508604],
                    [-69.7282905557199, -36.65463308583362],
                    [-69.72826446335993, -36.654718707416784],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '24',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 47,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72857149599997, -36.65487571299997],
                    [-69.72885703099996, -36.65489950699998],
                    [-69.7288644908866, -36.654809986165745],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72857149599997, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '25',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 48,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7285846370684, -36.654787034043004],
                    [-69.7288644908866, -36.654809986165745],
                    [-69.72887195077324, -36.65472046533151],
                    [-69.72859777813682, -36.65469835508604],
                    [-69.7285846370684, -36.654787034043004],
                  ],
                ],
              },
            },
          ],
        },
        taskTypes: ['Sacar fotos', 'Llenar formularios'],
      },
      {
        name: 'GeoVin',
        ownerId: '36e9ec13b985ec9c2d0fd9db',
        timeIntervals: [
          {
            name: 'a la tarde',
            startDate: new Date(),
            endDate: new Date('01/01/2026'),
            days: [1, 2, 3, 4, 5],
            time: {
              start: 0,
              end: 19,
            },
          } as TimeInterval,
          {
            name: 'finde morning',
            startDate: new Date(),
            endDate: new Date('01/01/2026'),
            days: [6, 7],
            time: {
              start: 0,
              end: 11,
            },
          } as TimeInterval,
        ],
        description:
          'Estudio de enfermedades transmitidas por vectores (animales transmisores).Proveer de herramientas interactivas, educativas, lúdicas y gratuitas a personas usuarias no especializadas, que permitan contribuir a la problemática relacionada con las vinchucas en todo el país.Fomentar la concientización acerca de la problemática de salud relacionada con la Enfermedad de Chagas, involucrando a la ciudadanía en el monitoreo de su vector.',
        image:
          'https://img.freepik.com/vector-gratis/paisaje-lago-diseno-plano_52683-76609.jpg',
        web: 'https://www.unq.edu.ar/',
        available: true,
        manualLocation: true,
        areas: {
          type: 'FeatureCollection',
          features: [
            {
              type: 'Feature',
              properties: {
                cid: '0',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 1,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72499997199998, -36.65485191799996],
                    [-69.7251911063333, -36.65485984966663],
                    [-69.72517993255157, -36.65512911127481],
                    [-69.72498879821825, -36.655121179608145],
                    [-69.72499997199998, -36.65485191799996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '1',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 2,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7251911063333, -36.65485984966663],
                    [-69.72538224066663, -36.6548677813333],
                    [-69.7253710668849, -36.65513704294148],
                    [-69.72517993255157, -36.65512911127481],
                    [-69.7251911063333, -36.65485984966663],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '2',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 3,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72538224066663, -36.6548677813333],
                    [-69.72557337499995, -36.65487571299997],
                    [-69.725525177603, -36.655138175770055],
                    [-69.7253710668849, -36.65513704294148],
                    [-69.72538224066663, -36.6548677813333],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '3',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 4,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72571614249995, -36.65492330199996],
                    [-69.72563092148776, -36.65517896593195],
                    [-69.725525177603, -36.655138175770055],
                    [-69.72557337499995, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '4',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 5,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72571614249995, -36.65492330199996],
                    [-69.72585890999994, -36.65497089099995],
                    [-69.7258550186, -36.65522778689421],
                    [-69.72563092148776, -36.65517896593195],
                    [-69.72571614249995, -36.65492330199996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '5',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 6,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72603736949995, -36.65491735324996],
                    [-69.72611480771225, -36.65517548110648],
                    [-69.7258550186, -36.65522778689421],
                    [-69.72585890999994, -36.65497089099995],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '6',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 7,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72603736949995, -36.65491735324996],
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72629326721226, -36.65512194335649],
                    [-69.72611480771225, -36.65517548110648],
                    [-69.72603736949995, -36.65491735324996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '7',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 8,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72639428849996, -36.654810277749974],
                    [-69.72647172671226, -36.6550684056065],
                    [-69.72629326721226, -36.65512194335649],
                    [-69.72621582899995, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '8',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 9,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72639428849996, -36.654810277749974],
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72661146710612, -36.65502055060449],
                    [-69.72647172671226, -36.6550684056065],
                    [-69.72639428849996, -36.654810277749974],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '9',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 10,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72677103666662, -36.65475673999998],
                    [-69.72677103666662, -36.65502623335248],
                    [-69.72661146710612, -36.65502055060449],
                    [-69.72657274799997, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '10',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 11,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72677103666662, -36.65475673999998],
                    [-69.72696932533329, -36.65475673999998],
                    [-69.72696932533329, -36.65502623335248],
                    [-69.72677103666662, -36.65502623335248],
                    [-69.72677103666662, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '11',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 12,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72696932533329, -36.65475673999998],
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72719906031293, -36.6550225126132],
                    [-69.72696932533329, -36.65502623335248],
                    [-69.72696932533329, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '12',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 13,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72736590233329, -36.65470915066663],
                    [-69.72742879495927, -36.65497120254058],
                    [-69.72719906031293, -36.6550225126132],
                    [-69.72716761399994, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '13',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 14,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72736590233329, -36.65470915066663],
                    [-69.72756419066663, -36.654661561333285],
                    [-69.7276270832926, -36.65492361320723],
                    [-69.72742879495927, -36.65497120254058],
                    [-69.72736590233329, -36.65470915066663],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '14',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 15,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72756419066663, -36.654661561333285],
                    [-69.72776247899998, -36.654613971999936],
                    [-69.7277438816084, -36.65487010706685],
                    [-69.7276270832926, -36.65492361320723],
                    [-69.72756419066663, -36.654661561333285],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '15',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 16,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72776247899998, -36.654613971999936],
                    [-69.72792110966664, -36.65467742433327],
                    [-69.72782102225753, -36.65492764259315],
                    [-69.7277438816084, -36.65487010706685],
                    [-69.72776247899998, -36.654613971999936],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '16',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 17,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72792110966664, -36.65467742433327],
                    [-69.72807974033331, -36.65474087666661],
                    [-69.7279796529242, -36.65499109492649],
                    [-69.72782102225753, -36.65492764259315],
                    [-69.72792110966664, -36.65467742433327],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '17',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 18,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72807974033331, -36.65474087666661],
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72816009392011, -36.65506119374942],
                    [-69.7279796529242, -36.65499109492649],
                    [-69.72807974033331, -36.65474087666661],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '18',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 19,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72840493349997, -36.654840020999956],
                    [-69.72834846674937, -36.655103532239025],
                    [-69.72816009392011, -36.65506119374942],
                    [-69.72823837099997, -36.654804328999944],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '19',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 20,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72840493349997, -36.654840020999956],
                    [-69.72857149599997, -36.65487571299997],
                    [-69.7285320727947, -36.65514174987086],
                    [-69.72834846674937, -36.655103532239025],
                    [-69.72840493349997, -36.654840020999956],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '20',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 21,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72857149599997, -36.65487571299997],
                    [-69.72871426349997, -36.654887609999975],
                    [-69.72869188384006, -36.655156172502686],
                    [-69.7285320727947, -36.65514174987086],
                    [-69.72857149599997, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '21',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 22,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72871426349997, -36.654887609999975],
                    [-69.72885703099996, -36.65489950699998],
                    [-69.72883465134005, -36.65516806950269],
                    [-69.72869188384006, -36.655156172502686],
                    [-69.72871426349997, -36.654887609999975],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '0',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 23,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72499997199998, -36.65485191799996],
                    [-69.72528667349997, -36.654863815499965],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72500369659389, -36.65476216413057],
                    [-69.72499997199998, -36.65485191799996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '1',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 24,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72500369659389, -36.65476216413057],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72529412268779, -36.65468430776117],
                    [-69.7250074211878, -36.65467241026117],
                    [-69.72500369659389, -36.65476216413057],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '2',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 25,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72528667349997, -36.654863815499965],
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72528667349997, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '3',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 26,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72560550659793, -36.65470073781991],
                    [-69.72529412268779, -36.65468430776117],
                    [-69.72529039809388, -36.65477406163057],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '4',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 27,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72557337499995, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '5',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 28,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72586150426658, -36.654799627070446],
                    [-69.72560550659793, -36.65470073781991],
                    [-69.72558944079894, -36.65478822540994],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '6',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 29,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72585890999994, -36.65497089099995],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '7',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 30,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72616420352509, -36.65469173026228],
                    [-69.72586150426658, -36.654799627070446],
                    [-69.72586020713325, -36.6548852590352],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '8',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 31,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72621582899995, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '9',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 32,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72654693526253, -36.65458086626364],
                    [-69.72616420352509, -36.65469173026228],
                    [-69.72619001626252, -36.65477777288112],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '10',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 33,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72687018099995, -36.65475673999998],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72657274799997, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '11',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 34,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72687018099995, -36.65457707776498],
                    [-69.72654693526253, -36.65458086626364],
                    [-69.72655984163126, -36.65466880313181],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '12',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 35,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72687018099995, -36.65475673999998],
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72687018099995, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '13',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 36,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72714664979128, -36.654579558257836],
                    [-69.72687018099995, -36.65457707776498],
                    [-69.72687018099995, -36.65466690888248],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '14',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 37,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72746504649996, -36.65468535599996],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72716761399994, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '15',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 38,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72715713189561, -36.65466814912891],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72742311808264, -36.65451065475066],
                    [-69.72714664979128, -36.654579558257836],
                    [-69.72715713189561, -36.65466814912891],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '16',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 39,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72746504649996, -36.65468535599996],
                    [-69.72776247899998, -36.654613971999936],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72746504649996, -36.65468535599996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '17',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 40,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7274440822913, -36.654598005375306],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72777487726103, -36.65444321528866],
                    [-69.72742311808264, -36.65451065475066],
                    [-69.7274440822913, -36.654598005375306],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '18',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 41,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72776247899998, -36.654613971999936],
                    [-69.72800042499998, -36.65470915049994],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72776247899998, -36.654613971999936],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '19',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 42,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72806714993939, -36.654542338326685],
                    [-69.72777487726103, -36.65444321528866],
                    [-69.7277686781305, -36.654528593644294],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '20',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 43,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72800042499998, -36.65470915049994],
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72800042499998, -36.65470915049994],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '21',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 44,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.7282905557199, -36.65463308583362],
                    [-69.72806714993939, -36.654542338326685],
                    [-69.72803378746968, -36.65462574441331],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '22',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 45,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72857149599997, -36.65487571299997],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.72823837099997, -36.654804328999944],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '23',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 46,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72826446335993, -36.654718707416784],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72859777813682, -36.65469835508604],
                    [-69.7282905557199, -36.65463308583362],
                    [-69.72826446335993, -36.654718707416784],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '24',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 47,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72857149599997, -36.65487571299997],
                    [-69.72885703099996, -36.65489950699998],
                    [-69.7288644908866, -36.654809986165745],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72857149599997, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '25',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 48,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7285846370684, -36.654787034043004],
                    [-69.7288644908866, -36.654809986165745],
                    [-69.72887195077324, -36.65472046533151],
                    [-69.72859777813682, -36.65469835508604],
                    [-69.7285846370684, -36.654787034043004],
                  ],
                ],
              },
            },
          ],
        },
        taskTypes: ['Sacar fotos', 'Llenar formularios'],
      },
      {
        name: 'ArgentiNat.org',
        ownerId: '66e9ec13b985ec9c2d0fd9db',
        timeIntervals: [
          {
            name: 'a la tarde',
            startDate: new Date(),
            endDate: new Date('01/01/2026'),
            days: [1, 2, 3, 4, 5],
            time: {
              start: 0,
              end: 19,
            },
          } as TimeInterval,
          {
            name: 'finde morning',
            startDate: new Date(),
            endDate: new Date('01/01/2026'),
            days: [6, 7],
            time: {
              start: 0,
              end: 11,
            },
          } as TimeInterval,
        ],
        description:
          'Biodiversidad.Conocer más acerca de los ciclos de vida, la distribución y la dinámica poblacional de todas las especies que habitan en Argentina',
        image:
          'https://img.freepik.com/vector-gratis/paisaje-lago-diseno-plano_52683-76609.jpg',
        web: 'https://www.unq.edu.ar/',
        available: true,
        manualLocation: true,
        areas: {
          type: 'FeatureCollection',
          features: [
            {
              type: 'Feature',
              properties: {
                cid: '0',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 1,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72499997199998, -36.65485191799996],
                    [-69.7251911063333, -36.65485984966663],
                    [-69.72517993255157, -36.65512911127481],
                    [-69.72498879821825, -36.655121179608145],
                    [-69.72499997199998, -36.65485191799996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '1',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 2,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7251911063333, -36.65485984966663],
                    [-69.72538224066663, -36.6548677813333],
                    [-69.7253710668849, -36.65513704294148],
                    [-69.72517993255157, -36.65512911127481],
                    [-69.7251911063333, -36.65485984966663],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '2',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 3,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72538224066663, -36.6548677813333],
                    [-69.72557337499995, -36.65487571299997],
                    [-69.725525177603, -36.655138175770055],
                    [-69.7253710668849, -36.65513704294148],
                    [-69.72538224066663, -36.6548677813333],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '3',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 4,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72571614249995, -36.65492330199996],
                    [-69.72563092148776, -36.65517896593195],
                    [-69.725525177603, -36.655138175770055],
                    [-69.72557337499995, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '4',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 5,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72571614249995, -36.65492330199996],
                    [-69.72585890999994, -36.65497089099995],
                    [-69.7258550186, -36.65522778689421],
                    [-69.72563092148776, -36.65517896593195],
                    [-69.72571614249995, -36.65492330199996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '5',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 6,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72603736949995, -36.65491735324996],
                    [-69.72611480771225, -36.65517548110648],
                    [-69.7258550186, -36.65522778689421],
                    [-69.72585890999994, -36.65497089099995],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '6',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 7,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72603736949995, -36.65491735324996],
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72629326721226, -36.65512194335649],
                    [-69.72611480771225, -36.65517548110648],
                    [-69.72603736949995, -36.65491735324996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '7',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 8,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72639428849996, -36.654810277749974],
                    [-69.72647172671226, -36.6550684056065],
                    [-69.72629326721226, -36.65512194335649],
                    [-69.72621582899995, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '8',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 9,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72639428849996, -36.654810277749974],
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72661146710612, -36.65502055060449],
                    [-69.72647172671226, -36.6550684056065],
                    [-69.72639428849996, -36.654810277749974],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '9',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 10,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72677103666662, -36.65475673999998],
                    [-69.72677103666662, -36.65502623335248],
                    [-69.72661146710612, -36.65502055060449],
                    [-69.72657274799997, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '10',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 11,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72677103666662, -36.65475673999998],
                    [-69.72696932533329, -36.65475673999998],
                    [-69.72696932533329, -36.65502623335248],
                    [-69.72677103666662, -36.65502623335248],
                    [-69.72677103666662, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '11',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 12,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72696932533329, -36.65475673999998],
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72719906031293, -36.6550225126132],
                    [-69.72696932533329, -36.65502623335248],
                    [-69.72696932533329, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '12',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 13,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72736590233329, -36.65470915066663],
                    [-69.72742879495927, -36.65497120254058],
                    [-69.72719906031293, -36.6550225126132],
                    [-69.72716761399994, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '13',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 14,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72736590233329, -36.65470915066663],
                    [-69.72756419066663, -36.654661561333285],
                    [-69.7276270832926, -36.65492361320723],
                    [-69.72742879495927, -36.65497120254058],
                    [-69.72736590233329, -36.65470915066663],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '14',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 15,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72756419066663, -36.654661561333285],
                    [-69.72776247899998, -36.654613971999936],
                    [-69.7277438816084, -36.65487010706685],
                    [-69.7276270832926, -36.65492361320723],
                    [-69.72756419066663, -36.654661561333285],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '15',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 16,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72776247899998, -36.654613971999936],
                    [-69.72792110966664, -36.65467742433327],
                    [-69.72782102225753, -36.65492764259315],
                    [-69.7277438816084, -36.65487010706685],
                    [-69.72776247899998, -36.654613971999936],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '16',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 17,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72792110966664, -36.65467742433327],
                    [-69.72807974033331, -36.65474087666661],
                    [-69.7279796529242, -36.65499109492649],
                    [-69.72782102225753, -36.65492764259315],
                    [-69.72792110966664, -36.65467742433327],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '17',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 18,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72807974033331, -36.65474087666661],
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72816009392011, -36.65506119374942],
                    [-69.7279796529242, -36.65499109492649],
                    [-69.72807974033331, -36.65474087666661],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '18',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 19,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72840493349997, -36.654840020999956],
                    [-69.72834846674937, -36.655103532239025],
                    [-69.72816009392011, -36.65506119374942],
                    [-69.72823837099997, -36.654804328999944],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '19',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 20,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72840493349997, -36.654840020999956],
                    [-69.72857149599997, -36.65487571299997],
                    [-69.7285320727947, -36.65514174987086],
                    [-69.72834846674937, -36.655103532239025],
                    [-69.72840493349997, -36.654840020999956],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '20',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 21,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72857149599997, -36.65487571299997],
                    [-69.72871426349997, -36.654887609999975],
                    [-69.72869188384006, -36.655156172502686],
                    [-69.7285320727947, -36.65514174987086],
                    [-69.72857149599997, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '21',
                pos: 'left',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 22,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72871426349997, -36.654887609999975],
                    [-69.72885703099996, -36.65489950699998],
                    [-69.72883465134005, -36.65516806950269],
                    [-69.72869188384006, -36.655156172502686],
                    [-69.72871426349997, -36.654887609999975],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '0',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 23,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72499997199998, -36.65485191799996],
                    [-69.72528667349997, -36.654863815499965],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72500369659389, -36.65476216413057],
                    [-69.72499997199998, -36.65485191799996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '1',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 24,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72500369659389, -36.65476216413057],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72529412268779, -36.65468430776117],
                    [-69.7250074211878, -36.65467241026117],
                    [-69.72500369659389, -36.65476216413057],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '2',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 25,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72528667349997, -36.654863815499965],
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72528667349997, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '3',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 26,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72529039809388, -36.65477406163057],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72560550659793, -36.65470073781991],
                    [-69.72529412268779, -36.65468430776117],
                    [-69.72529039809388, -36.65477406163057],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '4',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 27,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72557337499995, -36.65487571299997],
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72557337499995, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '5',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 28,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72558944079894, -36.65478822540994],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72586150426658, -36.654799627070446],
                    [-69.72560550659793, -36.65470073781991],
                    [-69.72558944079894, -36.65478822540994],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '6',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 29,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72585890999994, -36.65497089099995],
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72585890999994, -36.65497089099995],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '7',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 30,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72586020713325, -36.6548852590352],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72616420352509, -36.65469173026228],
                    [-69.72586150426658, -36.654799627070446],
                    [-69.72586020713325, -36.6548852590352],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '8',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 31,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72621582899995, -36.654863815499965],
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72621582899995, -36.654863815499965],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '9',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 32,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72619001626252, -36.65477777288112],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72654693526253, -36.65458086626364],
                    [-69.72616420352509, -36.65469173026228],
                    [-69.72619001626252, -36.65477777288112],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '10',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 33,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72657274799997, -36.65475673999998],
                    [-69.72687018099995, -36.65475673999998],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72657274799997, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '11',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 34,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72655984163126, -36.65466880313181],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72687018099995, -36.65457707776498],
                    [-69.72654693526253, -36.65458086626364],
                    [-69.72655984163126, -36.65466880313181],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '12',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 35,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72687018099995, -36.65475673999998],
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72687018099995, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '13',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 36,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72687018099995, -36.65466690888248],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72714664979128, -36.654579558257836],
                    [-69.72687018099995, -36.65457707776498],
                    [-69.72687018099995, -36.65466690888248],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '14',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 37,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72716761399994, -36.65475673999998],
                    [-69.72746504649996, -36.65468535599996],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72715713189561, -36.65466814912891],
                    [-69.72716761399994, -36.65475673999998],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '15',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 38,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72715713189561, -36.65466814912891],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72742311808264, -36.65451065475066],
                    [-69.72714664979128, -36.654579558257836],
                    [-69.72715713189561, -36.65466814912891],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '16',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 39,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72746504649996, -36.65468535599996],
                    [-69.72776247899998, -36.654613971999936],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.7274440822913, -36.654598005375306],
                    [-69.72746504649996, -36.65468535599996],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '17',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 40,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7274440822913, -36.654598005375306],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72777487726103, -36.65444321528866],
                    [-69.72742311808264, -36.65451065475066],
                    [-69.7274440822913, -36.654598005375306],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '18',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 41,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72776247899998, -36.654613971999936],
                    [-69.72800042499998, -36.65470915049994],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72776247899998, -36.654613971999936],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '19',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 42,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7277686781305, -36.654528593644294],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72806714993939, -36.654542338326685],
                    [-69.72777487726103, -36.65444321528866],
                    [-69.7277686781305, -36.654528593644294],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '20',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 43,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72800042499998, -36.65470915049994],
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72800042499998, -36.65470915049994],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '21',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 44,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72803378746968, -36.65462574441331],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.7282905557199, -36.65463308583362],
                    [-69.72806714993939, -36.654542338326685],
                    [-69.72803378746968, -36.65462574441331],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '22',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 45,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72823837099997, -36.654804328999944],
                    [-69.72857149599997, -36.65487571299997],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72826446335993, -36.654718707416784],
                    [-69.72823837099997, -36.654804328999944],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '23',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 46,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72826446335993, -36.654718707416784],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72859777813682, -36.65469835508604],
                    [-69.7282905557199, -36.65463308583362],
                    [-69.72826446335993, -36.654718707416784],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '24',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 47,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.72857149599997, -36.65487571299997],
                    [-69.72885703099996, -36.65489950699998],
                    [-69.7288644908866, -36.654809986165745],
                    [-69.7285846370684, -36.654787034043004],
                    [-69.72857149599997, -36.65487571299997],
                  ],
                ],
              },
            },
            {
              type: 'Feature',
              properties: {
                cid: '25',
                pos: 'right',
                gid: '264890',
                source_object: 'Acueducto',
                source_gna: 'Acueducto',
                id: 48,
              },
              geometry: {
                type: 'Polygon',
                coordinates: [
                  [
                    [-69.7285846370684, -36.654787034043004],
                    [-69.7288644908866, -36.654809986165745],
                    [-69.72887195077324, -36.65472046533151],
                    [-69.72859777813682, -36.65469835508604],
                    [-69.7285846370684, -36.654787034043004],
                  ],
                ],
              },
            },
          ],
        },
        taskTypes: ['Sacar fotos', 'Llenar formularios'],
      },
    ];

    return projects.map(async (p) => await this.projectService.create(p));
  }
}
