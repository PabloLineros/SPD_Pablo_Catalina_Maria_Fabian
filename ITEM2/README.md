# NortiShop - Entregable Técnico Criptográfico (ÍTEM II)

**Actividad N°2: "Del caso a los primeros riesgos - Cifrado de Datos Personales"**  
**Caso:** Caso 1 – Plataforma de comercio electrónico: **NortiShop**  
**Integrantes:**
- Catalina Toledo
- María Gerónimo
- Pablo Lineros

---

## Descripción del Proyecto

Este proyecto implementa la capa de protección criptográfica y seguridad para los datos personales y transaccionales de la plataforma **NortiShop**, tomando como base el diseño de la **Tabla por Campo Sensible** desarrollado en el **ÍTEM I**.

Se aplican los siguientes mecanismos conforme al estándar de la industria y las normativas de protección de datos (Ley 21.719 / GDPR / PCI-DSS / OWASP):

1. **Hashing Irreversible con Salting (`bcryptjs`)**: Para contraseñas (`password_hash`). Imposibilita la recuperación del texto plano ante filtraciones de bases de datos.
2. **Cifrado Simétrico Autenticado Reversible (`AES-256-GCM`)**: Para datos personales PII (`email`, `nombre`, `direccion_despacho`). Utiliza vectores de inicialización (IV) dinámicos únicos de 12 bytes y etiquetas de autenticación (auth tag) de 16 bytes para evitar adulteraciones en reposo.
3. **Tokenización de Medios de Pago (Cumplimiento PCI-DSS)**: Aislamiento del PAN de tarjetas bancarias mediante una bóveda externa (Vault), almacenando en NortiShop únicamente el `token_pago` y una máscara segura `mascara_tarjeta` (`************4582`).
4. **Control de Integridad con HMAC (`HMAC-SHA256`)**: Sellado criptográfico para saldos de puntos de fidelización (`saldo_puntos`), detectando cualquier manipulación o fraude.
5. **Gestión Segura de Secretos**: Exclusión estricta de llaves en el código fuente, carga desde `.env` y control de versiones protegido mediante `.gitignore` y `.env.example`.

---

## Estructura del Proyecto

```text
ITEM2/
├── .env.example                # Plantilla de variables de entorno para el repositorio
├── .env                        # Archivo local de configuración y llaves (ignorado en Git)
├── .gitignore                  # Reglas de exclusión de Git para evitar fugas de secretos
├── package.json                # Dependencias (bcryptjs, dotenv) y scripts
├── README.md                   # Instrucciones y visión general
├── INFORME_ITEM2.md            # Informe técnico detallado para la entrega académica
├── src/
│   ├── config/
│   │   └── env.js              # Validador Fail-Fast y cargador inmutable de configuración
│   ├── crypto/
│   │   ├── hashing.js          # Implementación de bcrypt con salt y auditoría de rounds
│   │   ├── cipher.js           # Implementación de AES-256-GCM con IV único y AuthTag
│   │   ├── integrity.js        # Implementación de HMAC-SHA256 con timingSafeEqual
│   │   └── tokenization.js     # Simulador de Vault PCI-DSS y tokenización de tarjetas
│   ├── db/
│   │   └── repository.js       # Base de datos simulada en memoria (Evidencia en reposo)
│   ├── services/
│   │   ├── userService.js      # Registro, login con bcrypt y perfil con descifrado PII
│   │   ├── orderService.js     # Despacho logístico y cobro por token
│   │   └── loyaltyService.js   # Gestión y sellado de NortiPuntos
│   └── demo.js                 # Script principal ejecutable con demostración interactiva
└── test/
    └── security.test.js        # Batería de pruebas automatizadas (node:test)
```

---

## Requisitos e Instalación

### Requisitos Previos
- **Node.js**: v18.0.0 o superior (verificado en v22.x).
- **npm**: v9.0.0 o superior.

### Instalación de Dependencias

Abra una terminal en la carpeta `ITEM2`:

```bash
cd ITEM2
npm install
```

---

## Ejecución y Pruebas

### 1. Demostración Interactiva en Consola (`demo.js`)
Ejecuta el flujo completo paso a paso mostrando el almacenamiento en reposo, login, descifrado, compra y detección de ataques:

```bash
npm start
```
*(o directamente: `node src/demo.js`)*

### 2. Ejecución de la Suite de Pruebas Automatizadas
Ejecuta las pruebas unitarias nativas para verificar la robustez de los algoritmos:

```bash
npm test
```

---

## Integrantes
- Catalina Toledo
- María Gerónimo
- Pablo Lineros
