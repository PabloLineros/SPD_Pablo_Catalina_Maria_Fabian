/**
 * Base de Datos Simulada en Reposo (Persistencia de NortiShop)
 * Este repositorio simula las tablas SQL/NoSQL en almacenamiento persistente.
 * Sirve como EVIDENCIA DIRECTA de que todos los datos almacenados en reposo
 * se encuentran estrictamente cifrados, hasheados o tokenizados.
 */

class DatabaseRepository {
  constructor() {
    this.users = new Map();
    this.loyaltyAccounts = new Map();
    this.orders = new Map();
  }

  // Operaciones de Usuario
  saveUser(userRecord) {
    this.users.set(userRecord.id, { ...userRecord });
    return this.users.get(userRecord.id);
  }

  getUserById(id) {
    const user = this.users.get(id);
    return user ? { ...user } : null;
  }

  getUserBySearchKey(field, value) {
    for (const user of this.users.values()) {
      if (user[field] === value) {
        return { ...user };
      }
    }
    return null;
  }

  // Operaciones de NortiPuntos
  saveLoyaltyAccount(accountRecord) {
    this.loyaltyAccounts.set(accountRecord.userId, { ...accountRecord });
    return this.loyaltyAccounts.get(accountRecord.userId);
  }

  getLoyaltyAccount(userId) {
    const acc = this.loyaltyAccounts.get(userId);
    return acc ? { ...acc } : null;
  }

  /**
   * Método de prueba de seguridad: Simula un atacante con acceso indebido directo a la BD
   * modificando manualmente el saldo de puntos sin actualizar la firma HMAC.
   */
  tamperLoyaltyPoints(userId, fakePoints) {
    const acc = this.loyaltyAccounts.get(userId);
    if (!acc) throw new Error('Cuenta no encontrada.');
    acc.saldo_puntos = fakePoints; // Se altera el saldo, pero el HMAC queda desincronizado
    this.loyaltyAccounts.set(userId, acc);
  }

  // Operaciones de Órdenes
  saveOrder(order) {
    this.orders.set(order.id, { ...order });
    return this.orders.get(order.id);
  }

  // Exportar volcado en crudo para auditoría
  getRawDatabaseDump() {
    return {
      usersTable: Array.from(this.users.values()),
      loyaltyTable: Array.from(this.loyaltyAccounts.values()),
      ordersTable: Array.from(this.orders.values())
    };
  }
}

export const DB = new DatabaseRepository();
