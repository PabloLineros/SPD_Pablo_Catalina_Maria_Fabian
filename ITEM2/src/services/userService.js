import crypto from 'node:crypto';
import { DB } from '../db/repository.js';
import { hashPassword, verifyPassword } from '../crypto/hashing.js';
import { encryptField, decryptField } from '../crypto/cipher.js';
import { PaymentVault } from '../crypto/tokenization.js';
import { LoyaltyService } from './loyaltyService.js';
import { assertPermission, ownerActor, ROLES } from '../security/accessControl.js';
import { CONFIG } from '../config/env.js';

/**
 * Servicio de Gestión de Usuarios y Autenticación de NortiShop
 * Aplica los principios de seguridad defensiva y ciclo de vida del dato:
 * - Contraseñas: Hashing irreversible (bcrypt).
 * - PII: Cifrado reversible simétrico (AES-256-GCM).
 * - Medios de Pago: Tokenización externa PCI-DSS.
 */
export class UserService {
  /**
   * Registra un nuevo cliente protegiendo cada atributo según su nivel de sensibilidad.
   */
  static async registerUser({ nombre, email, password, direccionDespacho, telefono, tarjeta }) {
    if (!nombre || !email || !password || !direccionDespacho) {
      throw new Error('Registro incompleto: nombre, email, contraseña y dirección son obligatorios.');
    }
    const userId = `usr_${crypto.randomUUID()}`;

    // 1. Hashing Irreversible de la Contraseña (bcrypt con factor de costo 12)
    const passwordHash = await hashPassword(password);

    // 2. Cifrado Simétrico Reversible en Reposo de Datos Personales (AES-256-GCM)
    // Cada campo obtiene su propio IV criptográfico aleatorio de 12 bytes
    const nombreCifrado = encryptField(nombre);
    const emailCifrado = encryptField(email);
    const direccionCifrada = encryptField(direccionDespacho);

    // 3. Tokenización del Medio de Pago (Delegación a Vault externo PCI-DSS)
    // El PAN nunca toca la persistencia de NortiShop
    const { token_pago, mascara_tarjeta, brand } = PaymentVault.tokenizeCard(tarjeta);

    // 4. Construcción del registro persistente
    const userRecord = {
      id: userId,
      nombre_cifrado: nombreCifrado,
      email_cifrado: emailCifrado,
      email_hmac: crypto.createHmac('sha256', CONFIG.HMAC_SECRET).update(email.toLowerCase()).digest('hex'),
      telefono_cifrado: telefono ? encryptField(telefono) : null,
      direccion_despacho_cifrada: direccionCifrada,
      password_hash: passwordHash,
      token_pago: token_pago,
      tarjeta_last4: mascara_tarjeta.slice(-4),
      tarjeta_marca: brand,
      role: ROLES.CUSTOMER,
      createdAt: new Date().toISOString()
    };

    // 5. Guardado en la base de datos
    DB.saveUser(userRecord);

    // 6. Asignación inicial de saldo de NortiPuntos con firma HMAC
    LoyaltyService.initializeAccount(userId, 500); // 500 puntos de bienvenida

    return {
      id: userRecord.id,
      role: userRecord.role,
      createdAt: userRecord.createdAt
    };
  }

  /**
   * Autenticación segura de usuario (Login).
   * Se valida la contraseña mediante 'bcrypt.compare' sin descifrar nada.
   * Para localizar al usuario, se busca descifrando de forma segura los emails en memoria
   * o utilizando el identificador de usuario.
   */
  static async authenticateUser(candidateEmail, candidatePassword) {
    // Localizar usuario descifrando de forma segura bajo demanda
    let targetUser = null;
    for (const user of DB.users.values()) {
      try {
        const decryptedEmail = decryptField(user.email_cifrado);
        if (decryptedEmail.toLowerCase() === candidateEmail.toLowerCase()) {
          targetUser = user;
          break;
        }
      } catch {
        // En caso de registro corrupto se ignora
      }
    }

    if (!targetUser) {
      return { success: false, reason: 'Credenciales inválidas (usuario no encontrado).' };
    }

    // Validación de contraseña mediante hashing seguro
    const isPasswordValid = await verifyPassword(candidatePassword, targetUser.password_hash);
    if (!isPasswordValid) {
      return { success: false, reason: 'Credenciales inválidas (contraseña incorrecta).' };
    }

    return {
      success: true,
      userId: targetUser.id,
      message: 'Autenticación exitosa validada por hash bcrypt.'
    };
  }

  /**
   * Recupera el perfil del usuario descifrando la PII bajo demanda para el titular autorizado.
   */
  static getUserProfile(userId, actor = ownerActor(userId)) {
    const permission = actor.role === ROLES.CUSTOMER && actor.userId === userId
      ? 'users:read:own'
      : 'users:read:any';
    assertPermission(actor, permission, userId);
    const user = DB.getUserById(userId);
    if (!user) {
      throw new Error(`Usuario ${userId} no encontrado.`);
    }

    // Descifrado bajo demanda con verificación de tag GCM
    const nombre = decryptField(user.nombre_cifrado);
    const email = decryptField(user.email_cifrado);
    const direccionDespacho = decryptField(user.direccion_despacho_cifrada);

    return {
      id: user.id,
      nombre,
      email,
      direccionDespacho,
      metodoPago: {
        last4: user.tarjeta_last4,
        marca: user.tarjeta_marca,
        token: actor.role === ROLES.ADMIN ? user.token_pago : '[RESTRINGIDO]'
      }
    };
  }
}
