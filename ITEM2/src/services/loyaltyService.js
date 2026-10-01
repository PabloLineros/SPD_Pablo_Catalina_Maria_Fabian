import { DB } from '../db/repository.js';
import { generateHMAC, verifyHMAC } from '../crypto/integrity.js';

/**
 * Servicio de Fidelización: NortiPuntos
 * Principio: Control de Integridad y Detección de Fraude mediante HMAC-SHA256.
 * El saldo de puntos no es un secreto criptográfico (el cliente lo visualiza en su cuenta),
 * pero debe garantizarse que nadie (ni administradores corruptos ni atacantes mediante inyección)
 * pueda alterar el valor en la base de datos sin invalidar la firma criptográfica del servidor.
 */
export class LoyaltyService {
  /**
   * Inicializa la cuenta de puntos del usuario y sella el saldo con HMAC.
   */
  static initializeAccount(userId, initialPoints = 0) {
    const signature = generateHMAC(initialPoints, userId);

    const record = {
      userId,
      saldo_puntos: initialPoints,
      hmac_firma: signature,
      ultima_actualizacion: new Date().toISOString()
    };

    DB.saveLoyaltyAccount(record);
    return record;
  }

  /**
   * Consulta el saldo actual de puntos verificando rigurosamente su integridad.
   */
  static getVerifiedBalance(userId) {
    const account = DB.getLoyaltyAccount(userId);
    if (!account) {
      throw new Error(`Cuenta de fidelización no encontrada para el usuario ${userId}`);
    }

    // Verificación criptográfica con HMAC-SHA256
    const isIntegrityValid = verifyHMAC(account.saldo_puntos, userId, account.hmac_firma);

    return {
      userId,
      saldo: account.saldo_puntos,
      firma: account.hmac_firma,
      integro: isIntegrityValid,
      estadoSeguridad: isIntegrityValid
        ? 'INTEGRIDAD_VERIFICADA: El saldo no ha sido alterado.'
        : 'ALERTA_DE_SEGURIDAD: FRAUDE DETECTADO. El saldo ha sido manipulado en la base de datos.'
    };
  }

  /**
   * Redime puntos de la cuenta tras validar exitosamente la firma del saldo previo.
   */
  static redeemPoints(userId, pointsToRedeem) {
    const verification = this.getVerifiedBalance(userId);

    if (!verification.integro) {
      throw new Error(`Operación Bloqueada por Seguridad: Se detectó una inconsistencia de integridad en el saldo del usuario ${userId}.`);
    }

    if (verification.saldo < pointsToRedeem) {
      throw new Error(`Saldo insuficiente: Tienes ${verification.saldo} puntos y deseas redimir ${pointsToRedeem}.`);
    }

    const nuevoSaldo = verification.saldo - pointsToRedeem;
    const nuevaFirma = generateHMAC(nuevoSaldo, userId);

    const updatedRecord = {
      userId,
      saldo_puntos: nuevoSaldo,
      hmac_firma: nuevaFirma,
      ultima_actualizacion: new Date().toISOString()
    };

    DB.saveLoyaltyAccount(updatedRecord);
    return {
      success: true,
      puntosRedimidos: pointsToRedeem,
      nuevoSaldo,
      nuevaFirma
    };
  }
}
