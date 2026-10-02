# NortiShop — Implementación de controles criptográficos

**Entregable técnico — Ítem II**  
**Actividad:** Del caso a los primeros riesgos: cifrado de datos personales  
**Caso de estudio:** Plataforma de comercio electrónico NortiShop

## Integrantes

- Catalina Toledo
- María Gerónimo
- Pablo Lineros

## 1. Descripción del proyecto

Este proyecto presenta una implementación académica de controles criptográficos para proteger datos personales y transaccionales de la plataforma ficticia NortiShop. Se basa en el análisis de campos sensibles desarrollado en el Ítem I.

La solución incorpora los siguientes mecanismos:

1. **Hashing de contraseñas con `bcryptjs`:** almacena contraseñas como hashes con sal y un factor de costo configurable. El proceso no permite recuperar la contraseña original a partir del hash.
2. **Cifrado autenticado AES-256-GCM:** protege información personal identificable (PII), como correos electrónicos y direcciones. Utiliza un vector de inicialización (IV) aleatorio y una etiqueta de autenticación para detectar modificaciones.
3. **Tokenización simulada de medios de pago:** sustituye el número de tarjeta (PAN) por un token y conserva una máscara para su identificación visual. La bóveda incluida en este proyecto es únicamente un simulador académico; no procesa pagos reales ni acredita cumplimiento de PCI DSS.
4. **Verificación de integridad mediante HMAC-SHA256:** permite detectar modificaciones no autorizadas en los saldos de puntos de fidelización.
5. **Configuración mediante variables de entorno:** obtiene las claves criptográficas y otros parámetros de configuración desde el entorno de ejecución, en lugar de definirlos directamente en el código fuente.

> **Alcance:** este proyecto tiene fines educativos. Su implementación no constituye una certificación ni garantiza, por sí sola, el cumplimiento de leyes, normas o estándares de seguridad.

## 2. Estructura del proyecto

```text
ITEM2/
├── .env.example                # Plantilla de configuración sin secretos de uso real
├── .env                        # Configuración local; no debe incluirse en Git
├── .gitignore                  # Exclusiones para archivos locales y secretos
├── package.json                # Dependencias y comandos del proyecto
├── README.md                   # Documentación del proyecto
├── src/
│   ├── config/
│   │   └── env.js              # Carga y validación de la configuración
│   ├── crypto/
│   │   ├── hashing.js          # Hashing de contraseñas con bcrypt
│   │   ├── cipher.js           # Cifrado y descifrado AES-256-GCM
│   │   ├── integrity.js        # Generación y verificación de HMAC-SHA256
│   │   └── tokenization.js     # Simulador académico de tokenización
│   ├── db/
│   │   └── repository.js       # Repositorio simulado en memoria
│   ├── services/
│   │   ├── userService.js      # Registro, autenticación y consulta de perfiles
│   │   ├── orderService.js     # Flujo simulado de pedidos y cobros por token
│   │   └── loyaltyService.js   # Gestión e integridad de puntos
│   └── demo.js                 # Demostración del flujo principal
└── test/
    └── security.test.js        # Pruebas automatizadas de seguridad
```

## 3. Requisitos

- **Node.js:** versión 18 o superior.
- **npm:** versión 9 o superior.

## 4. Instalación y configuración

Desde una terminal, ingresa al directorio del proyecto e instala las dependencias:

```bash
cd ITEM2
npm install
```

Crea una configuración local a partir de la plantilla:

```bash
cp .env.example .env
```

Edita `.env` y define valores adecuados para el entorno local. La clave AES-256 debe corresponder a 32 bytes, normalmente representados por 64 caracteres hexadecimales. Para generar una clave aleatoria desde Node.js:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

El archivo `.env` contiene valores de configuración sensibles: no debe subirse a Git ni compartirse. `.env.example` debe contener únicamente nombres de variables y valores de ejemplo no utilizables como secretos reales.

## 5. Ejecución

### Demostración

Para ejecutar el flujo de demostración:

```bash
npm start
```

También puede ejecutarse directamente:

```bash
node src/demo.js
```

### Pruebas automatizadas

Para ejecutar la suite de pruebas:

```bash
npm test
```

Las pruebas verifican el hashing de contraseñas, el cifrado y la detección de alteraciones, la tokenización simulada, la integridad de los puntos y el flujo de servicios.

## 6. Consideraciones de seguridad que deben ser recalcadas pero que no se consideraron en este caso:
- No se deben almacenar claves reales en el código fuente ni en archivos que se suban al repositorio, si no que deben estar en un archivo .env
- Los valores de `.env.example` deben ser marcadores o datos ficticios, nunca credenciales activas.
- Si una clave real se publica o se comparte accidentalmente, debe considerarse comprometida y reemplazarse inmediatamente!
