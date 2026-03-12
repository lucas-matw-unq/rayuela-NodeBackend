import { User } from '../../auth/users/user.entity';
import { Checkin } from '../entities/checkin.entity';
import { CheckInDocument, CheckInTemplate } from './checkin.schema';

export class CheckinMapper {
  /**
   * Transforma una entidad Checkin a su template para persistencia (CheckInTemplate)
   * @param checkin Instancia de la entidad Checkin
   * @returns Una instancia de CheckInTemplate con los datos mapeados
   */
  static toTemplate(checkin: Checkin): CheckInTemplate {
    return new CheckInTemplate(
      checkin.latitude,
      checkin.longitude,
      checkin.date,
      checkin.projectId,
      checkin.user.id,
      checkin.contributesTo,
      checkin.taskType,
      checkin.imageRef,
    );
  }

  /**
   * Transforma un template (CheckInTemplate) a la entidad de dominio Checkin
   * @param template Instancia de CheckInTemplate obtenida de la base de datos
   * @param user Instancia completa del usuario asociado
   * @returns Una instancia de Checkin con los datos mapeados
   */
  static toEntity(template: CheckInDocument, user: User): Checkin {
    const checkin = new Checkin(
      template.latitude,
      template.longitude,
      template.datetime,
      template.projectId,
      user,
      template.taskType,
      template._id,
      null,
      template.imageRef,
    );

    // Si el template tiene información de contributesTo, se actualiza en la entidad
    if (template.contributesTo) {
      checkin.validateContribution(template.contributesTo);
    }
    return checkin;
  }

}
