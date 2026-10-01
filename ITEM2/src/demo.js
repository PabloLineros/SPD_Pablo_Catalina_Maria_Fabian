import { CONFIG } from './config/env.js';
import { UserService } from './services/userService.js';
import { OrderService } from './services/orderService.js';
import { LoyaltyService } from './services/loyaltyService.js';
import { DB } from './db/repository.js';
import { inspectBcryptHash } from './crypto/hashing.js';
import { inspectCipherPayload, decryptField } from './crypto/cipher.js';

// Constantes de estilo ANSI para la consola
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const MAGENTA = '\x1b[35m';
const BLUE = '\x1b[34m';
const DIM = '\x1b[2m';

function printHeader(title) {
  console.log(`\n${CYAN}${BOLD}================================================================================${RESET}`);
  console.log(`${CYAN}${BOLD} ${title.toUpperCase()}${RESET}`);
  console.log(`${CYAN}${BOLD}================================================================================${RESET}`);
}

function printSubHeader(subtitle) {
  console.log(`\n${YELLOW}${BOLD}>>> ${subtitle}${RESET}`);
}

async function runDemonstration() {
  console.log(`${MAGENTA}${BOLD}`);
  console.log('╔══════════════════════════════════════════════════════════════════════════════╗');
  console.log('║       NORTISHOP - DEMOSTRACIÓN DE PROTECCIÓN CRIPTOGRÁFICA (ÍTEM II)         ║');
  console.log('║      Actividad N°2: "Del caso a los primeros riesgos - Cifrado de Datos"     ║');
  console.log('║      Integrantes: Catalina Toledo | María Gerónimo | Pablo Lineros           ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════════╝');
  console.log(RESET);

  // ---------------------------------------------------------------------------
  // FASE 1: GESTIÓN SEGURA DE LLAVES Y CONFIGURACIÓN (NO EXPOSICIÓN DE SECRETOS)
  // ---------------------------------------------------------------------------
  printHeader('Fase 1: Verificación de Gestión Segura de Secretos y Llaves');
  console.log(`${GREEN}✔ Secretos cargados exitosamente desde variables de entorno (process.env):${RESET}`);
  console.log(`  - Llave Simétrica AES-256 : ${CYAN}[PROTEGIDA EN MEMORIA]${RESET} (${CONFIG.AES_KEY.length * 8} bits / ${CONFIG.AES_KEY.length} bytes)`);
  console.log(`  - Secreto HMAC-SHA256     : ${CYAN}[PROTEGIDO EN MEMORIA]${RESET} (Entropía: ${CONFIG.HMAC_SECRET.length} caracteres)`);
  console.log(`  - Factor Costo bcrypt     : ${CONFIG.BCRYPT_ROUNDS} rondas (2^${CONFIG.BCRYPT_ROUNDS} = ${2 ** CONFIG.BCRYPT_ROUNDS} iteraciones)`);
  console.log(`  - Llave API Pasarela      : ${CONFIG.PAYMENT_GATEWAY_API_KEY.substring(0, 10)}... [Máscara de seguridad]`);
  console.log(`\n${BLUE}ℹ Control de versiones resguardado:${RESET}`);
  console.log(`  - Archivo '.env' excluido explícitamente en '.gitignore'.`);
  console.log(`  - Archivo '.env.example' disponible como plantilla libre de secretos para el repositorio.`);

  // ---------------------------------------------------------------------------
  // FASE 2: REGISTRO DE USUARIO CON PROTECCIÓN MULTICAPA DE CAMPOS
  // ---------------------------------------------------------------------------
  printHeader('Fase 2: Registro de Cliente en NortiShop (Aplicación de Criptografía)');
  
  const datosEntradaCliente = {
    nombre: 'Catalina Andrea Toledo Pérez',
    email: 'catalina.toledo@alumnos.nortishop.cl',
    password: 'PasswordSuperSegura2026!#',
    direccionDespacho: 'Avenida Angamos 0610, Depto 402, Antofagasta, Región de Antofagasta',
    tarjeta: {
      pan: '4532117890124582',
      cardHolder: 'CATALINA A TOLEDO',
      expirationDate: '12/28',
      cvv: '892'
    }
  };

  console.log(`${BOLD}Datos originales ingresados por el usuario en el formulario web (en tránsito vía TLS):${RESET}`);
  console.log(`  - Nombre             : ${datosEntradaCliente.nombre}`);
  console.log(`  - Email              : ${datosEntradaCliente.email}`);
  console.log(`  - Contraseña plana   : ${datosEntradaCliente.password}`);
  console.log(`  - Dirección Despacho : ${datosEntradaCliente.direccionDespacho}`);
  console.log(`  - Tarjeta (PAN)      : ${datosEntradaCliente.tarjeta.pan} (CVV: ${datosEntradaCliente.tarjeta.cvv})`);

  console.log(`\n${YELLOW}Procesando registro en el backend...${RESET}`);
  const usuarioCreado = await UserService.registerUser(datosEntradaCliente);
  console.log(`${GREEN}✔ Usuario registrado satisfactoriamente con ID: ${usuarioCreado.id}${RESET}`);

  // ---------------------------------------------------------------------------
  // FASE 3: EVIDENCIA DE DATOS EN REPOSO EN LA BASE DE DATOS
  // ---------------------------------------------------------------------------
  printHeader('Fase 3: Evidencia de Datos en Reposo (Inspección Física de la Base de Datos)');
  console.log(`${BOLD}Así es como un atacante o administrador vería los registros almacenados en el disco/BD:${RESET}\n`);

  const rawUser = DB.getUserById(usuarioCreado.id);
  const rawLoyalty = DB.getLoyaltyAccount(usuarioCreado.id);

  console.log(`${CYAN}TABLA 'users':${RESET}`);
  console.log(JSON.stringify({
    id: rawUser.id,
    nombre_cifrado: rawUser.nombre_cifrado,
    email_cifrado: rawUser.email_cifrado,
    direccion_despacho_cifrada: rawUser.direccion_despacho_cifrada,
    password_hash: rawUser.password_hash,
    token_pago: rawUser.token_pago,
    mascara_tarjeta: rawUser.mascara_tarjeta,
    tarjeta_marca: rawUser.tarjeta_marca,
    createdAt: rawUser.createdAt
  }, null, 2));

  console.log(`\n${CYAN}TABLA 'loyalty_accounts' (NortiPuntos con integridad sellada):${RESET}`);
  console.log(JSON.stringify(rawLoyalty, null, 2));

  printSubHeader('Análisis Criptográfico de los Campos Almacenados:');
  
  // Inspección de bcrypt
  const hashAnalysis = inspectBcryptHash(rawUser.password_hash);
  console.log(`1. ${BOLD}Campo 'password_hash' (bcrypt irreversible):${RESET}`);
  console.log(`   - Algoritmo    : ${hashAnalysis.algorithm}`);
  console.log(`   - Factor Costo : ${hashAnalysis.costFactorRounds} (${hashAnalysis.iterations} rondas de hashing lento)`);
  console.log(`   - Salt Cripto  : ${hashAnalysis.saltBase64} (generado aleatoriamente)`);
  console.log(`   - Digest Hash  : ${hashAnalysis.hashDigest}`);
  console.log(`   ${GREEN}✔ Resultado: Es matemáticamente imposible revertir el hash a la contraseña original.${RESET}`);

  // Inspección de AES-256-GCM
  const cipherAnalysis = inspectCipherPayload(rawUser.email_cifrado);
  console.log(`\n2. ${BOLD}Campo 'email_cifrado' (AES-256-GCM autenticado):${RESET}`);
  console.log(`   - Formato      : IV (hex) : AuthTag (hex) : Ciphertext (hex)`);
  console.log(`   - IV Único     : ${cipherAnalysis.ivHex} (${cipherAnalysis.ivBytes} bytes / 96 bits aleatorios)`);
  console.log(`   - AuthTag      : ${cipherAnalysis.authTagHex} (${cipherAnalysis.authTagBytes} bytes para verificar autenticidad)`);
  console.log(`   - Criptograma  : ${cipherAnalysis.ciphertextHex}`);
  console.log(`   ${GREEN}✔ Resultado: Confidencialidad y autenticidad garantizadas. Un IV nuevo por cada registro evita patrones.${RESET}`);

  // Inspección de Tokenización PCI-DSS
  console.log(`\n3. ${BOLD}Campos 'token_pago' y 'mascara_tarjeta' (Tokenización PCI-DSS):${RESET}`);
  console.log(`   - Token Pago   : ${rawUser.token_pago} (Identificador opaco de Vault externo)`);
  console.log(`   - Máscara      : ${rawUser.mascara_tarjeta} (Cumple PCI-DSS Requisito 3.3)`);
  console.log(`   ${GREEN}✔ Resultado: Cero riesgo de fuga de tarjetas. El PAN '4532117890124582' NO existe en NortiShop.${RESET}`);

  // Inspección de HMAC
  console.log(`\n4. ${BOLD}Campo 'saldo_puntos' con 'hmac_firma' (HMAC-SHA256):${RESET}`);
  console.log(`   - Saldo visible: ${rawLoyalty.saldo_puntos} puntos`);
  console.log(`   - Firma HMAC   : ${rawLoyalty.hmac_firma}`);
  console.log(`   ${GREEN}✔ Resultado: Detección instantánea si un atacante altera su puntaje en la base de datos.${RESET}`);

  // ---------------------------------------------------------------------------
  // FASE 4: VALIDACIÓN DE CONTRASEÑA EN LOGIN (SIN DESCIFRAR)
  // ---------------------------------------------------------------------------
  printHeader('Fase 4: Validación de Credenciales en Inicio de Sesión (Login)');
  console.log('¿Cómo se valida la contraseña si es irreversible y nunca se descifra?');
  console.log('-> El servidor toma la contraseña candidata, aplica el mismo salt con bcrypt y compara los hashes resultantes.');

  printSubHeader('Caso 4.1: Intento de Login con Contraseña Incorrecta:');
  const loginFallido = await UserService.authenticateUser(
    'catalina.toledo@alumnos.nortishop.cl',
    'PasswordEquivocada123'
  );
  console.log(`Intentando ingresar con 'PasswordEquivocada123'...`);
  console.log(`Respuesta del Backend: ${RED}Rechazado -> ${loginFallido.reason}${RESET}`);

  printSubHeader('Caso 4.2: Intento de Login con Contraseña Correcta:');
  const loginExitoso = await UserService.authenticateUser(
    'catalina.toledo@alumnos.nortishop.cl',
    'PasswordSuperSegura2026!#'
  );
  console.log(`Intentando ingresar con 'PasswordSuperSegura2026!#'...`);
  console.log(`Respuesta del Backend: ${GREEN}Aprobado -> ${loginExitoso.message} (UserID: ${loginExitoso.userId})${RESET}`);

  // ---------------------------------------------------------------------------
  // FASE 5: RECUPERACIÓN DE PII BAJO DEMANDA Y VERIFICACIÓN DE INTEGRIDAD GCM
  // ---------------------------------------------------------------------------
  printHeader('Fase 5: Recuperación de PII Bajo Demanda (Descifrado Reversible AES-256-GCM)');
  console.log('Cuando el usuario ingresa a su "Perfil de Usuario", el sistema descifra temporalmente en memoria:');

  const perfilDescifrado = UserService.getUserProfile(usuarioCreado.id);
  console.log(`\n${GREEN}✔ Perfil descifrado en memoria para renderizar en vista de cliente:${RESET}`);
  console.log(`  - Nombre Completo    : ${perfilDescifrado.nombre}`);
  console.log(`  - Correo Electrónico : ${perfilDescifrado.email}`);
  console.log(`  - Dirección Despacho : ${perfilDescifrado.direccionDespacho}`);
  console.log(`  - Método de Pago     : ${perfilDescifrado.metodoPago.marca} terminada en ${perfilDescifrado.metodoPago.mascara}`);

  printSubHeader('Caso 5.2: Prueba de Tampering / Adulteración en Criptograma (Seguridad GCM):');
  console.log('Simulando que un atacante modifica un solo bit del correo cifrado en la base de datos...');
  
  // Alteramos intencionalmente el último carácter del ciphertext
  const payloadOriginal = rawUser.email_cifrado;
  const parts = payloadOriginal.split(':');
  const tamperedCiphertext = parts[2].substring(0, parts[2].length - 2) + 'ff';
  const payloadAlterado = `${parts[0]}:${parts[1]}:${tamperedCiphertext}`;

  try {
    decryptField(payloadAlterado);
  } catch (error) {
    console.log(`${RED}⛔ ALERTA GCM: Descifrado bloqueado exitosamente.${RESET}`);
    console.log(`   Detalle de la excepción criptográfica: ${YELLOW}${error.message}${RESET}`);
    console.log(`   ${GREEN}✔ Se demostró que AES-256-GCM detecta alteraciones en tránsito o en reposo.${RESET}`);
  }

  // ---------------------------------------------------------------------------
  // FASE 6: COMPRA RECURRENTE MEDIANTE TOKENIZACIÓN (PCI-DSS) Y DESPACHO
  // ---------------------------------------------------------------------------
  printHeader('Fase 6: Compra y Despacho Logístico (Tokenización + Descifrado Just-in-Time)');
  console.log('El cliente realiza una nueva compra en NortiShop por un monto de $45.990 CLP.');
  console.log('NortiShop no pide el número de tarjeta nuevamente: envía el token_pago a la Pasarela Externa.');

  const nuevaOrden = OrderService.processOrder(
    usuarioCreado.id,
    ['Polerón Universitario NortiShop', 'Taza Térmica'],
    45990
  );

  console.log(`\n${GREEN}✔ Compra Aprobada:${RESET}`);
  console.log(`  - ID Orden            : ${nuevaOrden.id}`);
  console.log(`  - ID Transacción Auth : ${nuevaOrden.transaccionId}`);
  console.log(`  - Código Autorización : ${nuevaOrden.codigoAutorizacion}`);
  console.log(`  - Tarjeta Usada       : ${nuevaOrden.mascaraTarjetaUsada}`);
  console.log(`  - Estado de Orden     : ${nuevaOrden.estado}`);
  console.log(`  - Etiqueta Despacho   : "${nuevaOrden.direccionDespachoDescifradaLogistica}" (descifrada bajo demanda para el repartidor)`);

  // ---------------------------------------------------------------------------
  // FASE 7: DETECCIÓN DE FRAUDE EN NORTIPUNTOS (CONTROL DE INTEGRIDAD CON HMAC)
  // ---------------------------------------------------------------------------
  printHeader('Fase 7: Fidelización NortiPuntos y Detección de Fraude mediante HMAC-SHA256');
  
  printSubHeader('Caso 7.1: Consulta legítima del saldo de NortiPuntos:');
  const balanceLegitimo = LoyaltyService.getVerifiedBalance(usuarioCreado.id);
  console.log(`Saldo actual: ${balanceLegitimo.saldo} puntos`);
  console.log(`Firma HMAC  : ${balanceLegitimo.firma}`);
  console.log(`Resultado   : ${GREEN}${balanceLegitimo.estadoSeguridad}${RESET}`);

  printSubHeader('Caso 7.2: Redención legítima de 150 puntos:');
  const redencion = LoyaltyService.redeemPoints(usuarioCreado.id, 150);
  console.log(`Puntos redimidos : ${redencion.puntosRedimidos}`);
  console.log(`Nuevo saldo      : ${redencion.nuevoSaldo} puntos`);
  console.log(`Nueva firma HMAC : ${redencion.nuevaFirma}`);
  console.log(`${GREEN}✔ Transacción de saldo firmada y confirmada.${RESET}`);

  printSubHeader('Caso 7.3: Intento de Fraude / Manipulación de Puntos en la Base de Datos:');
  console.log('Un atacante vulnera la BD y modifica su saldo de 350 a 999.999 puntos...');
  DB.tamperLoyaltyPoints(usuarioCreado.id, 999999);

  const balanceAlterado = LoyaltyService.getVerifiedBalance(usuarioCreado.id);
  console.log(`Saldo en la BD tras el hack : ${balanceAlterado.saldo} puntos`);
  console.log(`Resultado de la verificación: ${RED}${balanceAlterado.estadoSeguridad}${RESET}`);

  console.log('\nIntentando redimir puntos fraudulentos...');
  try {
    LoyaltyService.redeemPoints(usuarioCreado.id, 1000);
  } catch (err) {
    console.log(`${RED}⛔ OPERACIÓN DETENIDA: ${err.message}${RESET}`);
    console.log(`${GREEN}✔ La firma HMAC-SHA256 evitó el fraude exitosamente.${RESET}`);
  }

  // ---------------------------------------------------------------------------
  // FASE 8: RESUMEN DE CUMPLIMIENTO TÉCNICO Y NORMATIVO
  // ---------------------------------------------------------------------------
  printHeader('Fase 8: Resumen de Cumplimiento Técnico y Normativo (NortiShop)');
  console.log(`
${BOLD}Resumen de Controles Criptográficos Implementados:${RESET}
┌──────────────────────┬───────────────────────┬──────────────────────────┬─────────────────────────────┐
│ Campo Crítico        │ Técnica Criptográfica │ Algoritmo Estándar       │ Cumplimiento / Justificación │
├──────────────────────┼───────────────────────┼──────────────────────────┼─────────────────────────────┤
│ password_hash        │ Hashing Irreversible  │ bcrypt (12 rounds + salt)│ Deber de diligencia (OWASP) │
│ email_cifrado        │ Cifrado Simétrico     │ AES-256-GCM (IV 12b)     │ Ley 21.719 / Reversible     │
│ direccion_despacho   │ Cifrado Simétrico     │ AES-256-GCM (IV 12b)     │ Confidencialidad PII        │
│ token_pago / mascara │ Tokenización Externa  │ Vault Opaco (PCI-DSS)    │ PCI-DSS Requirement 3.3     │
│ saldo_puntos         │ Control de Integridad │ HMAC-SHA256              │ Prevención de fraude activo │
│ llaves / secretos    │ Gestión de Secretos   │ .env + .gitignore        │ Principio de No Exposición  │
└──────────────────────┴───────────────────────┴──────────────────────────┴─────────────────────────────┘
  `);
  console.log(`${GREEN}${BOLD}Demostración finalizada con éxito. Todos los requisitos del Ítem II han sido satisfechos.${RESET}\n`);
}

runDemonstration().catch(err => {
  console.error('Error fatal durante la demostración:', err);
  process.exit(1);
});
