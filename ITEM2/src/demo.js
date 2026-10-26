import { API } from './api.js';
import { DB } from './db/repository.js';
import { describirLlavero } from './crypto/keyring.js';
import { inspectBcryptHash } from './crypto/hashing.js';
import { logger } from './security/logger.js';
import { prepararEscenario, ok, PASSWORD_PRUEBA, TARJETA_VISA } from './dev/escenario.js';

/**
 * Demostración por consola de los controles de minimización, seudonimización/anonimización,
 * RBAC y protección criptográfica. Todos los datos son SINTÉTICOS (src/dev/escenario.js).
 * Su salida sirve como evidencia de ejecución para el informe.
 */

const C = { B: '\x1b[1m', R: '\x1b[0m', CY: '\x1b[36m', G: '\x1b[32m', Y: '\x1b[33m', RD: '\x1b[31m', D: '\x1b[2m' };

const titulo = (t) => console.log(`\n${C.CY}${C.B}${'═'.repeat(80)}\n ${t}\n${'═'.repeat(80)}${C.R}`);
const sub = (t) => console.log(`\n${C.Y}${C.B}▶ ${t}${C.R}`);
const json = (o) => console.log(C.D + JSON.stringify(o, null, 2) + C.R);

function resultado(etiqueta, r) {
  if (r.ok) console.log(`  ${C.G}✔ PERMITIDO${C.R}  ${etiqueta}`);
  else console.log(`  ${C.RD}⛔ ${r.error.codigo.padEnd(24)}${C.R} ${etiqueta} ${C.D}— ${r.error.mensaje}${C.R}`);
  return r;
}

async function main() {
  console.log(`${C.B}NortiShop — Minimización, Seudonimización, RBAC y Criptografía (datos sintéticos)${C.R}`);
  console.log('Integrantes: Catalina Toledo | María Gerónimo | Pablo Lineros | Fabián Salinas');

  const { tokens, ids } = await prepararEscenario();

  // ---------------------------------------------------------------------------
  titulo('0. Gestión de llaves');
  console.log('Una llave por finalidad, cargada desde el entorno y retirada de process.env:');
  for (const l of describirLlavero()) console.log(`  - ${l.finalidad.padEnd(11)} ${l.bits} bits  ${C.D}[valor nunca expuesto]${C.R}`);
  console.log(`  - process.env.KEY_CIFRADO_AES256 después de cargar: ${process.env.KEY_CIFRADO_AES256}`);

  // ---------------------------------------------------------------------------
  titulo('Parte 1. Minimización de datos');
  const base = { nombre: 'Carla Demo', email: 'carla@ejemplo.test', password: PASSWORD_PRUEBA, direccionDespacho: 'Avenida Sintética 99', comuna: 'Iquique' };

  sub('El servidor rechaza datos que no son necesarios');
  resultado('Registro con fecha_nacimiento', await API.auth.registrar({ ...base, fecha_nacimiento: '1999-01-01' }));
  resultado('Registro con sexo y foto', await API.auth.registrar({ ...base, sexo: 'F', foto: 'base64...' }));
  resultado('Tarjeta sin marcar "guardar medio de pago"', await API.auth.registrar({ ...base, tarjeta: TARJETA_VISA }));
  resultado('Boleta con RUT de facturación', await API.cliente.crearPedido(tokens.clienteA, {
    items: [{ productoId: ids.productos[0], cantidad: 1 }], tipoDocumento: 'BOLETA',
    facturacion: { rut: '76.086.428-5', razonSocial: 'Empresa Ficticia SpA', direccion: 'Oficina 1' }
  }));
  resultado('Registro mínimo (sin teléfono ni tarjeta)', await API.auth.registrar(base));

  sub('Pedido válido: monto calculado en el servidor, solo last4 de la tarjeta');
  json(ok(await API.cliente.crearPedido(tokens.clienteA, { items: [{ productoId: ids.productos[0], cantidad: 2 }] })));

  sub('La capa de datos también lo impide (lista blanca de columnas y tipos protegidos)');
  try {
    DB.conectar('svc_app').insertar('users', { id: crypto.randomUUID(), fecha_nacimiento: '1999-01-01' });
  } catch (e) {
    console.log(`  ${C.RD}⛔ ${e.code}${C.R} ${e.message}`);
  }

  // ---------------------------------------------------------------------------
  titulo('Parte 1/4. Datos en reposo (lo que vería un atacante con acceso a la BD)');
  const fisico = DB.simularAccesoFisico();
  const user = fisico.users.find(u => u.id === ids.clienteA);
  json({ tabla: 'users', ...user });
  json({ tabla: 'orders', ...fisico.orders[0] });
  const h = inspectBcryptHash(user.password_hash);
  console.log(`  password_hash: ${h.algorithm}, costo ${h.costFactorRounds} (${h.iterations} iteraciones)`);

  sub('AAD: copiar el email cifrado de Ana al registro de Bruno no sirve');
  DB.manipularFilaDirecto('users', ids.clienteB, { email_cifrado: user.email_cifrado });
  resultado('Bruno lee su perfil con el criptograma ajeno (GCM rechaza el AAD; el detalle solo va al log)', await API.cliente.verPerfil(tokens.clienteB, ids.clienteB));
  DB.manipularFilaDirecto('users', ids.clienteB, { email_cifrado: fisico.users.find(u => u.id === ids.clienteB).email_cifrado });

  // ---------------------------------------------------------------------------
  titulo('Parte 2. Seudonimización y anonimización');

  sub('Reseña: en la tabla se guarda HMAC(K_resenas, user_id); el público solo ve el alias');
  ok(await API.cliente.publicarResena(tokens.clienteA, { productoId: ids.productos[0], calificacion: 5, alias: 'ana_p', comentario: '<b>Muy bueno</b>' }));
  console.log('  Fila almacenada:');
  json(DB.simularAccesoFisico().resenas[0]);
  console.log('  Vista pública v_resenas_publicas:');
  json(ok(await API.catalogo.resenas(ids.productos[0])));

  sub('Analítica: ETL seudonimiza (HMAC con K_analitica) y generaliza (mes, rango, categoría, comuna)');
  for (let i = 0; i < 5; i++) {
    const email = `k${i}@ejemplo.test`;
    ok(await API.auth.registrar({ nombre: `Cliente K ${i}`, email, password: PASSWORD_PRUEBA, direccionDespacho: `Calle K ${i}`, comuna: 'Antofagasta' }));
    const { token } = ok(await API.auth.iniciarSesion({ email, password: PASSWORD_PRUEBA }));
    ok(await API.cliente.crearPedido(token, { items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));
  }
  ok(await API.cliente.crearPedido(tokens.clienteB, { items: [{ productoId: ids.productos[1], cantidad: 1 }], tarjeta: TARJETA_VISA }));
  json(ok(await API.privacidad.ejecutarEtl(tokens.privacidad)));
  console.log('  Ejemplo de fila en analitica.compras (lo que ve el ANALISTA):');
  json(ok(await API.analitica.compras(tokens.analista))[0]);

  sub('Reporte anonimizado (k = 5): el grupo de Calama (1 cliente) se suprime');
  console.table(ok(await API.analitica.ventasPorComuna(tokens.analista)));

  sub('Invitado: seguimiento por token aleatorio; contacto anonimizado al vencer el plazo');
  const { tokenSeguimiento } = ok(await API.invitado.crearPedido({
    nombre: 'Invitado Demo', email: 'invitado@ejemplo.test', direccionDespacho: 'Calle Invitada 77', comuna: 'Arica',
    items: [{ productoId: ids.productos[0], cantidad: 1 }], tarjeta: TARJETA_VISA
  }));
  json(ok(await API.invitado.consultarPedido(tokenSeguimiento)));
  const refInvitado = DB.simularAccesoFisico().envios.find(e => e.tipo_pedido === 'INVITADO').ref_envio;
  ok(await API.logistica.actualizarEstado(tokens.logistica, refInvitado, 'EN_RUTA'));
  ok(await API.logistica.actualizarEstado(tokens.logistica, refInvitado, 'ENTREGADO'));
  console.log(`  Job hoy:          ${JSON.stringify(ok(await API.privacidad.anonimizarInvitados(tokens.privacidad, new Date())))}`);
  console.log(`  Job en 91 días:   ${JSON.stringify(ok(await API.privacidad.anonimizarInvitados(tokens.privacidad, new Date(Date.now() + 91 * 86_400_000))))}`);
  const inv = DB.simularAccesoFisico().orders_invitado[0];
  json({ nombre: inv.nombre_invitado_cifrado, email: inv.email_invitado_cifrado, direccion: inv.direccion_envio_cifrada, total_clp: inv.total_clp, estado: inv.estado });

  sub('Marketing: solo consentimientos vigentes, identificados por seudónimo de marketing');
  json(ok(await API.marketing.exportarSuscriptores(tokens.marketing)));

  sub('Reidentificación: solo OFICIAL_PRIVACIDAD con motivo documentado');
  const pseudoId = DB.simularAccesoFisico().resenas[0].autor_pseudo;
  const reid = { pseudoId, finalidad: 'resenas', motivo: 'Requerimiento judicial causa ficticia 123' };
  resultado('ADMINISTRADOR intenta revertir seudónimo', await API.privacidad.revertirSeudonimo(tokens.admin, reid));
  resultado('OFICIAL_PRIVACIDAD revierte seudónimo (auditado)', await API.privacidad.revertirSeudonimo(tokens.privacidad, reid));

  // ---------------------------------------------------------------------------
  titulo('Parte 3/4. RBAC: accesos permitidos y denegados en el servidor');
  const ref = ok(await API.logistica.pendientes(tokens.logistica))[0].ref_envio;
  const intentos = [
    ['CLIENTE (Bruno) lee el perfil de Ana', API.cliente.verPerfil(tokens.clienteB, ids.clienteA)],
    ['CLIENTE (Ana) lee su propio perfil', API.cliente.verPerfil(tokens.clienteA, ids.clienteA)],
    ['CLIENTE intenta listar todos los pedidos', API.pedidos.listar(tokens.clienteA)],
    ['ANALISTA intenta buscar un cliente por email', API.soporte.buscarCliente(tokens.analista, 'ana.prueba@ejemplo.test')],
    ['SOPORTE busca cliente (vista enmascarada)', API.soporte.buscarCliente(tokens.soporte, 'ana.prueba@ejemplo.test')],
    ['SOPORTE revela PII sin ticket válido', API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: 'x', motivo: 'x' })],
    ['SOPORTE revela PII con ticket y motivo', API.soporte.revelarDatosContacto(tokens.soporte, ids.clienteA, { ticket: 'TCK-1001', motivo: 'Cliente reporta pedido no recibido' })],
    ['ADMINISTRADOR intenta revelar PII', API.soporte.revelarDatosContacto(tokens.admin, ids.clienteA, { ticket: 'TCK-1001', motivo: 'Cliente reporta pedido no recibido' })],
    ['ADMINISTRADOR se auto-asigna OFICIAL_PRIVACIDAD', API.admin.asignarRol(tokens.admin, ids.admin, 'OFICIAL_PRIVACIDAD')],
    ['LOGISTICA genera etiqueta de despacho', API.logistica.etiqueta(tokens.logistica, ref)],
    ['LOGISTICA intenta exportar suscriptores', API.marketing.exportarSuscriptores(tokens.logistica)],
    ['MARKETING intenta leer analítica fila a fila', API.analitica.compras(tokens.marketing)],
    ['CATALOGO intenta leer auditoría', API.admin.auditoria(tokens.catalogo)],
    ['Sin sesión: consultar perfil', API.cliente.verPerfil(undefined, ids.clienteA)]
  ];
  for (const [etiqueta, promesa] of intentos) {
    const r = resultado(etiqueta, await promesa);
    if (r.ok && /enmascarada|etiqueta/.test(etiqueta)) json(r.data);
  }

  sub('Revocación inmediata: MARKETING pasa a ANALISTA con la sesión abierta');
  ok(await API.admin.asignarRol(tokens.admin, ids.marketing, 'ANALISTA'));
  resultado('Misma sesión intenta exportar suscriptores', await API.marketing.exportarSuscriptores(tokens.marketing));

  sub('Login sin enumeración de usuarios');
  resultado('Email inexistente', await API.auth.iniciarSesion({ email: 'nadie@ejemplo.test', password: 'x'.repeat(12) }));
  resultado('Email existente, clave incorrecta', await API.auth.iniciarSesion({ email: 'ana.prueba@ejemplo.test', password: 'x'.repeat(12) }));

  // ---------------------------------------------------------------------------
  titulo('Parte 4. Integridad de NortiPuntos (HMAC + versión + historial)');
  const filaAntigua = DB.simularAccesoFisico().loyalty_accounts.find(a => a.user_id === ids.clienteB);
  json(ok(await API.cliente.canjearPuntos(tokens.clienteB, ids.clienteB, 100)));
  DB.manipularFilaDirecto('loyalty_accounts', ids.clienteB, filaAntigua);
  resultado('Atacante restaura fila antigua con firma válida y consulta saldo', await API.cliente.saldoPuntos(tokens.clienteB, ids.clienteB));
  DB.manipularFilaDirecto('loyalty_accounts', ids.clienteB, { saldo_puntos: 999999 });
  resultado('Atacante fija saldo en 999.999 e intenta canjear', await API.cliente.canjearPuntos(tokens.clienteB, ids.clienteB, 1000));

  // ---------------------------------------------------------------------------
  titulo('Parte 4. Registros de actividad y auditoría (sin datos personales)');
  sub('Últimos registros de actividad (redactados automáticamente)');
  for (const r of logger.registros().slice(-5)) console.log(`  ${C.D}${JSON.stringify(r)}${C.R}`);
  sub('Últimas entradas de auditoría');
  console.table(ok(await API.admin.auditoria(tokens.admin, { limite: 8 })).map(({ actor_rol, accion, recurso, resultado: res, motivo }) => ({ actor_rol, accion, recurso, resultado: res, motivo })));

  console.log(`\n${C.G}${C.B}Demostración finalizada.${C.R} Ejecute ${C.B}npm test${C.R} para la batería completa de pruebas.\n`);
}

main().catch((err) => {
  console.error('Error fatal durante la demostración:', logger.registros().length ? err.message : err);
  process.exit(1);
});
