import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Post,
  UseGuards,
} from '@nestjs/common';
import { Role } from 'src/roles/roles.enum';
import { Roles } from 'src/roles/role.decorator';
import { RolesGuard } from 'src/roles/roles.guard';
import { AuthGuard } from './auth.guard';
import { CreateUserDTO } from './create-user-dto';
import { UsersService } from './users.service';

@Controller('admin/users')
@UseGuards(AuthGuard, RolesGuard)
@Roles(Role.Admin)
export class AdminController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  @Post()
  create(@Body() createUserDTO: CreateUserDTO) {
    return this.usersService.signup(createUserDTO);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id', ParseIntPipe) id: number): Promise<void> {
    await this.usersService.remove(id);
  }
}
