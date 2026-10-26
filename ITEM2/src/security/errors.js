/**
 * Manejo seguro de errores.
 * Cada error tiene un CÓDIGO estable y un MENSAJE PÚBLICO que nunca incluye datos personales,
 * llaves, tokens ni trazas internas. El detalle técnico (si existe) solo va al log, redactado.
 */

const ESTADOS = Object.freeze({
  DATO_INVALIDO: 400,
  CAMPO_NO_PERMITIDO: 400,
  NO_AUTENTICADO: 401,
  CREDENCIALES_INVALIDAS: 401,
  ACCESO_DENEGADO: 403,
  CUENTA_BLOQUEADA: 423,
  NO_ENCONTRADO: 404,
  CONFLICTO: 409,
  INTEGRIDAD_COMPROMETIDA: 409,
  ERROR_INTERNO: 500
});

export class AppError extends Error {
  /**
   * @param {keyof ESTADOS} codigo
   * @param {string} mensajePublico Mensaje seguro de mostrar al cliente.
   */
  constructor(codigo, mensajePublico) {
    super(mensajePublico);
    this.name = 'AppError';
    this.codigo = codigo;
    this.estado = ESTADOS[codigo] ?? 500;
  }
}

export const errores = {
  datoInvalido: (msg) => new AppError('DATO_INVALIDO', msg),
  campoNoPermitido: (campos) => new AppError('CAMPO_NO_PERMITIDO', `Campos no permitidos por la política de minimización: ${campos.join(', ')}.`),
  noAutenticado: () => new AppError('NO_AUTENTICADO', 'Sesión inválida o expirada.'),
  credencialesInvalidas: () => new AppError('CREDENCIALES_INVALIDAS', 'Credenciales inválidas.'),
  accesoDenegado: () => new AppError('ACCESO_DENEGADO', 'No tiene permisos para realizar esta operación.'),
  cuentaBloqueada: () => new AppError('CUENTA_BLOQUEADA', 'Cuenta bloqueada temporalmente por intentos fallidos.'),
  noEncontrado: (recurso = 'Recurso') => new AppError('NO_ENCONTRADO', `${recurso} no encontrado.`),
  conflicto: (msg) => new AppError('CONFLICTO', msg),
  integridad: () => new AppError('INTEGRIDAD_COMPROMETIDA', 'Operación bloqueada: se detectó una inconsistencia de integridad.')
};

/** Convierte cualquier excepción en una respuesta pública segura. */
export function respuestaDeError(error) {
  if (error instanceof AppError) {
    return { codigo: error.codigo, estado: error.estado, mensaje: error.message };
  }
  return { codigo: 'ERROR_INTERNO', estado: 500, mensaje: 'Ocurrió un error interno. Intente nuevamente.' };
}
