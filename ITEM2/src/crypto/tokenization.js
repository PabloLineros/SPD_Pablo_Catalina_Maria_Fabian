import crypto from 'node:crypto';

/**
 * Módulo Criptográfico / Arquitectónico: Tokenización de Medios de Pago
 * Principio: Cumplimiento de PCI-DSS (Payment Card Industry Data Security Standard).
 * El e-commerce NortiShop NUNCA debe almacenar en sus bases de datos números de tarjeta (PAN),
 * fechas de vencimiento ni códigos CVV.
 *
 * En su lugar, el cliente envía la tarjeta directamente a una Pasarela/Vault externo.
 * La bóveda externa custodia el PAN y emite:
 * 1. Un TOKEN opaco (sin relación matemática reversible con el PAN).
 * 2. Los ÚLTIMOS 4 DÍGITOS y la marca (minimización: no se entrega una máscara completa
 *    porque revela el largo del PAN).
 *
 * Este simulador NO guarda el PAN ni una huella de él: un SHA-256 sin sal de un PAN es
 * reversible por fuerza bruta (el espacio de números de tarjeta es pequeño).
 */

function luhnValido(pan) {
  let suma = 0;
  let doblar = false;
  for (let i = pan.length - 1; i >= 0; i--) {
    let d = Number(pan[i]);
    if (doblar) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    suma += d;
    doblar = !doblar;
  }
  return suma % 10 === 0;
}

function detectarMarca(pan) {
  if (/^4/.test(pan)) return 'VISA';
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(pan)) return 'MASTERCARD';
  if (/^3[47]/.test(pan)) return 'AMERICAN_EXPRESS';
  return 'OTRA';
}

class MockPaymentVault {
  constructor() {
    // Bóveda aislada simulada (en producción, esto reside en la infraestructura de la pasarela)
    this.vault = new Map();
  }

  /**
   * Recibe datos de tarjeta desde el cliente y genera un token seguro.
   * El CVV se valida pero nunca se almacena (PCI-DSS 3.3.1.2).
   * @param {object} cardData { pan, expirationDate, cvv }
   * @returns {object} { token_pago, last4, brand }
   */
  tokenizeCard({ pan, expirationDate, cvv } = {}) {
    const sanitizedPan = String(pan ?? '').replace(/[\s-]/g, '');

    if (!/^\d{13,19}$/.test(sanitizedPan) || !luhnValido(sanitizedPan)) {
      throw new Error('Número de tarjeta inválido.');
    }
    if (!/^\d{3,4}$/.test(String(cvv ?? ''))) {
      throw new Error('Código de seguridad inválido.');
    }
    if (!/^(0[1-9]|1[0-2])\/\d{2}$/.test(String(expirationDate ?? ''))) {
      throw new Error('Fecha de vencimiento inválida (MM/AA).');
    }

    const token_pago = `tok_norti_vault_${crypto.randomBytes(16).toString('hex')}`;
    const last4 = sanitizedPan.slice(-4);
    const brand = detectarMarca(sanitizedPan);

    // En una bóveda real aquí se custodiaría el PAN cifrado; el simulador no lo necesita.
    this.vault.set(token_pago, { brand, createdAt: new Date().toISOString() });

    return { token_pago, last4, brand };
  }

  /**
   * Ejecuta un cobro simulado utilizando el token de pago previamente emitido.
   * @param {string} tokenPago Token registrado del cliente.
   * @param {number} amount Monto de la compra en CLP.
   */
  chargeWithToken(tokenPago, amount) {
    if (!Number.isInteger(amount) || amount <= 0) {
      throw new Error('Monto de cobro inválido.');
    }
    const cardInfo = this.vault.get(tokenPago);
    if (!cardInfo) {
      // No se incluye el token en el mensaje: los errores terminan en logs.
      throw new Error('Transacción rechazada: medio de pago no válido o expirado.');
    }

    return {
      success: true,
      transactionId: `tx_auth_${crypto.randomBytes(8).toString('hex')}`,
      authorizationCode: String(crypto.randomInt(100000, 1000000)),
      amount,
      currency: 'CLP',
      brand: cardInfo.brand,
      timestamp: new Date().toISOString()
    };
  }

  /** Invalida un token (cuando el cliente elimina su medio de pago o su cuenta). */
  revokeToken(tokenPago) {
    this.vault.delete(tokenPago);
  }
}

// Instancia singleton de la bóveda de pagos externa simulada
export const PaymentVault = new MockPaymentVault();
