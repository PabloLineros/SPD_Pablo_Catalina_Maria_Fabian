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
 * 2. Una MÁSCARA segura (solo últimos 4 dígitos) para fines de UX (visualización en panel).
 */

class MockPaymentVault {
  constructor() {
    // Bóveda aislada simulada (en producción, esto reside en la infraestructura de Stripe/Transbank)
    this.vault = new Map();
  }

  /**
   * Recibe datos de tarjeta desde el cliente y genera un token seguro.
   * @param {object} cardData { pan, cardHolder, expirationDate, cvv }
   * @returns {object} { token_pago, mascara_tarjeta, brand }
   */
  tokenizeCard({ pan, cardHolder, expirationDate, cvv }) {
    // Limpieza del PAN
    const sanitizedPan = String(pan).replace(/\s+/g, '').replace(/-/g, '');

    if (!/^\d{13,19}$/.test(sanitizedPan)) {
      throw new Error('Número de tarjeta (PAN) inválido. Debe contener entre 13 y 19 dígitos.');
    }

    if (!cvv || String(cvv).length < 3) {
      throw new Error('Código CVV inválido.');
    }

    // 1. Generación de Token Opaco Criptográfico (UUID v4 + prefijo de entorno)
    const tokenBytes = crypto.randomBytes(16).toString('hex');
    const token_pago = `tok_norti_vault_${tokenBytes}`;

    // 2. Generación de Máscara de Tarjeta según norma PCI-DSS Requirement 3.3
    // Solo se conservan legibles los últimos 4 dígitos. El resto se enmascara con '*'
    const last4 = sanitizedPan.slice(-4);
    const maskedLength = sanitizedPan.length - 4;
    const mascara_tarjeta = `${'*'.repeat(maskedLength)}${last4}`;

    // Determinación de marca de tarjeta
    let brand = 'VISA';
    if (sanitizedPan.startsWith('5')) brand = 'MASTERCARD';
    else if (sanitizedPan.startsWith('3')) brand = 'AMERICAN_EXPRESS';

    // 3. Almacenamiento seguro EXCLUSIVO en la bóveda externa (fuera de la BD de NortiShop)
    this.vault.set(token_pago, {
      panHash: crypto.createHash('sha256').update(sanitizedPan).digest('hex'),
      cardHolder,
      expirationDate,
      brand,
      createdAt: new Date().toISOString()
    });

    // 4. Retorno a la aplicación NortiShop: ÚNICAMENTE token y máscara
    return {
      token_pago,
      mascara_tarjeta,
      brand
    };
  }

  /**
   * Ejecuta un cobro simulado utilizando el token de pago previamente emitido.
   * La aplicación de comercio electrónico nunca conoce ni procesa el PAN.
   * @param {string} tokenPago Token registrado del cliente.
   * @param {number} amount Monto de la compra.
   */
  chargeWithToken(tokenPago, amount) {
    if (!this.vault.has(tokenPago)) {
      throw new Error(`Transacción rechazada: El token de pago '${tokenPago}' no existe o ha expirado.`);
    }

    const cardInfo = this.vault.get(tokenPago);
    const transactionId = `tx_auth_${crypto.randomBytes(8).toString('hex')}`;
    const authorizationCode = Math.floor(100000 + Math.random() * 900000).toString();

    return {
      success: true,
      transactionId,
      authorizationCode,
      amount,
      currency: 'CLP',
      brand: cardInfo.brand,
      timestamp: new Date().toISOString()
    };
  }
}

// Instancia singleton de la bóveda de pagos externa simulada
export const PaymentVault = new MockPaymentVault();
