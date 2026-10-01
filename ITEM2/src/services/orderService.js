import crypto from 'node:crypto';
import { DB } from '../db/repository.js';
import { decryptField } from '../crypto/cipher.js';
import { PaymentVault } from '../crypto/tokenization.js';

/**
 * Servicio de Órdenes y Logística de Despacho
 * Demuestra:
 * 1. Uso del token de pago recurrente sin consultar ni tocar datos PAN.
 * 2. Descifrado just-in-time (en memoria) de la dirección de despacho para la etiqueta logística.
 */
export class OrderService {
  /**
   * Procesa una compra para un usuario registrado.
   */
  static processOrder(userId, items, totalAmount) {
    const user = DB.getUserById(userId);
    if (!user) {
      throw new Error(`Usuario ${userId} no encontrado.`);
    }

    // 1. Cobro seguro utilizando el Token de Pago guardado en la BD
    const paymentResult = PaymentVault.chargeWithToken(user.token_pago, totalAmount);

    // 2. Descifrado bajo demanda de la dirección de despacho para logística
    const direccionDespachoPlana = decryptField(user.direccion_despacho_cifrada);

    const orderId = `ord_${crypto.randomUUID().substring(0, 8)}`;
    const orderRecord = {
      id: orderId,
      userId,
      items,
      totalAmount,
      transaccionId: paymentResult.transactionId,
      codigoAutorizacion: paymentResult.authorizationCode,
      mascaraTarjetaUsada: user.mascara_tarjeta,
      estado: 'PAGADA_Y_PREPARANDO_DESPACHO',
      direccionDespachoDescifradaLogistica: direccionDespachoPlana,
      createdAt: new Date().toISOString()
    };

    DB.saveOrder(orderRecord);
    return orderRecord;
  }
}
