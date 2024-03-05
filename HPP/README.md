
## HTTP Parameter Pollution (HPP)

## Introducción
Este tipo de ataque se basa en la manipulación de los parámetros de las peticiones HTTP que realiza una aplicación web a su *backend/servidor*. Esto se hace para tratar de manipular la lógica de procesamiento de los parámetros y que la aplicación web tenga un comportamiento inesperado .

Por ejemplo en una petición a esta URL:
```url
https://bitcoin.com/transfer?from=1337&to=8008&amount=1000 
```

Un atacante podría probar a añadir otro parámetro `from`:
```url
https://bitcoin.com/transfer?from=1337&to=8008&amount=1000&from=6733
```
Si la aplicación web es vulnerable a HPP, esta acción podría resultar fatal.

## Causas Comunes
La vulnerabilidad a este tipo de ataque viene de la forma en la que la aplicación web procesa y valida los parámetros HTTP que recibe.
1. **Manejo inconsistente de parámetros duplicados:** Cuando una aplicación o servidor recibe una solicitud HTTP con múltiples instancias del mismo parámetro, la forma en que se manejan estos parámetros duplicados puede variar. Algunos servidores o *frameworks* toman el primer valor, otros el último, y algunos intentan combinarlos. 
   
   Para evitar esta aleatoriedad es preciso que se defina de una forma consistente el uso de los parámetros, ya que de otro modo esta inconsistencia puede ser explotada por los atacantes para manipular la lógica de la aplicación.
2. **Falta de validación y saneamiento de entrada:** Una causa común de vulnerabilidades de seguridad, incluido HPP, es la falta de validación o saneamiento adecuado de los datos de entrada. Cuando una aplicación no verifica ni limpia adecuadamente los valores de los parámetros que recibe y confía en el *input*, puede ser susceptible a ataques que inyecten datos maliciosos o manipulen la lógica de la aplicación.
3. **Interpretación ambigua de parámetros en aplicaciones multifuncionales:** Las aplicaciones que ofrecen múltiples funcionalidades y servicios pueden interpretar de manera diferente los parámetros dependiendo del contexto. Si un atacante puede enviar parámetros de manera que sean interpretados de forma ambigua o incorrecta, puede influir en la lógica de la aplicación.
Esta es una pequeña tabla de [OWASP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution) sobre como se comportan algunas tecnologías a la manipulación de parámetros:

Dada la URL y la búsqueda: `http://example.com/?color=red&color=blue`

| Servidor de Aplicación Web                            | Resultado del parsing                                 | Ejemplo               |
| ----------------------------------------------------- | ----------------------------------------------------- | --------------------- |
| ASP.NET / IIS                                         | Todas las ocurrencias concatenadas con coma           | `color=ro, azul`      |
| ASP / IIS                                             | Todas las ocurrencias concatenadas con coma           | `color=ro, azul`      |
| .NET Core 3.1 / Kestrel                               | Todas las ocurrencias concatenadas con coma           | `color=ro, azul`      |
| .NET 5 / Kestrel                                      | Todas las ocurrencias concatenadas con coma           | `color=ro, azul`      |
| PHP / Apache                                          | Última ocurrencia                                     | `color=azul`          |
| PHP / Zeus                                            | Última ocurrencia                                     | `color=azul`          |
| JSP, Servlet / Apache Tomcat                          | Primera ocurrencia                                    | `color=ro`            |
| JSP, Servlet / Servidor de Aplicaciones de Oracle 10g | Primera ocurrencia                                    | `color=ro`            |
| JSP, Servlet / Jetty                                  | Primera ocurrencia                                    | `color=ro`            |
| IBM Lotus Domino                                      | Última ocurrencia                                     | `color=azul`          |
| Servidor HTTP de IBM                                  | Primera ocurrencia                                    | `color=ro`            |
| Node.js / express                                     | Primera ocurrencia                                    | `color=ro`            |
| mod-perl, libapreq2 / Apache                          | Primera ocurrencia                                    | `color=ro`            |
| Perl CGI / Apache                                     | Primera ocurrencia                                    | `color=ro`            |
| mod.wsgi (Python) / Apache                            | Primera ocurrencia                                    | `color=ro`            |
| Python / Zope                                         | Todas las ocurrencias en el tipo de datos de la Lista | `color=[-red-,-blue]` |

## Tipos

### HPP de Lado del Servidor (Server-Side HPP)
En este caso, es el servidor el encargado de procesar los parámetros que le llegan, como en el ejemplo de la introducción, un atacante puede agregar más parámetros para engañar al servidor (este suele coger el primero o el último por lo general), si el servidor esta mal configurado, realizará la acción que el atacante quiera.
Algunas consecuencias:
- **Sobreescritura de parámetros:** El servidor puede considerar solo uno de los valores, lo que permite al atacante sobrescribir valores legítimos con valores maliciosos.
- **Concatenación de valores:** Algunos servidores concatenan los valores de parámetros duplicados, lo que puede ser explotado para inyectar valores inesperados o maliciosos.
- **Comportamiento indefinido:** En algunos casos, el comportamiento del servidor ante parámetros duplicados puede ser impredecible, lo que puede llevar a vulnerabilidades de seguridad si el atacante logra explotar esta incertidumbre.

### HPP de Lado del Cliente (Client-Side HPP)
El HPP de lado del cliente se produce cuando la manipulación de los parámetros afecta a como la aplicación web (frontend) procesa estos parámetros, viéndose reflejado en el cliente.. Este tipo de HPP explota cómo los scripts del lado del cliente manejan los parámetros pasados a través de la URL o de otras fuentes.
Esta vulnerabilidad puede llevar ataques XSS, manipulación del DOM...
Por ejemplo una URL de esta estructura:
La web recoge el parámetro *user* para dar una bienvenida al usuario:
```url
 https://www.ejemplo.com/?user=Juan
```

Y el código JavaScript puede ser así:
```javascript
window.onload = function() {
  // Obtener el parámetro 'user' de la URL
  var userName = new URLSearchParams(window.location.search).get('user');
  // Mostrar un mensaje de bienvenida personalizado
  document.getElementById('welcomeMessage').innerHTML = 'Bienvenido, ' + userName;
};
```

El usuario podría manipular este parámetro para introducir un script malicioso:
`https://www.ejemplo.com/?user=<script>alert('Ataque XSS');</script>`
En este caso se utiliza la técnica HPP para realizar un XSS reflejado.


## Pasos de explotación

Las pruebas para este tipo de ataque suelen basarse en probar parámetros y analizar el comportamiento.

- ****HPP de Lado del Servidor***:  Para este tipo de vulnerabilidad, podríamos primeramente utilizar herramientas de escaneo como *Wappalyzer* o *WhatWeb* en terminal para averiguar que infraestructura corre por detrás de la aplicación web. Si tenemos la suerte de poder averiguar que tipo de servidor esta detrás, podremos buscar información sobre como el servidor y la tecnología de la aplicación web valida por defecto los parámetros para tratar de vulnerarlos. 
  Si nos es imposible averiguar el servidor, tendremos que ir probando los parámetros y  analizando el comportamiento ante la manipulación de la URL.
  Cabe destacar que lo más cómodo es usar un *proxy* , para ver todos los parámetros de la petición, pueden estarse mandando más de los que la URL muestra.
- ****HPP de Lado del Cliente**** : Similar al HPP de lado del servidor, tendremos que ir probando a manipular los parámetros (eliminar,añadir,duplicar...) y ver como nuestro cliente procesa los datos de la URL, también podemos usar herramientas de escaneo para identificar el *framework* web que la aplicación utiliza par averiguar como por defecto maneja los parámetros.
  Importante recalcar que en la forma en que el navegador procesa los datos de la URL puede afectar al *payload* enviado, para evitar estos problemas asegúrate de mandarlos en formato *url-encode*.  
  `  <script>alert('XSS')</script>`  ➜ `%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E
`
## Implicaciones
La Polución de Parámetros HTTP (HPP) puede tener varias implicaciones de seguridad para una aplicación web, resumidas de forma general en los siguientes puntos:

1. **Manipulación de la Lógica de la Aplicación:** Los atacantes pueden alterar el flujo normal de la aplicación, llevando a resultados no previstos como el acceso a funciones restringidas, la alteración de comportamientos de la aplicación, o la modificación de datos.

2. **Evasión de Controles de Seguridad:** HPP puede permitir a los atacantes evadir controles de seguridad como filtros de entrada, validaciones de formulario, y medidas de autenticación o autorización, comprometiendo la integridad y confidencialidad de la aplicación.

3. **Cross-Site Scripting (XSS):** En el contexto de HPP de lado del cliente, la inyección de scripts maliciosos mediante parámetros manipulados puede llevar a ataques XSS, poniendo en riesgo la seguridad de los usuarios al permitir el robo de cookies, sesiones, o datos personales.

4. **Denegación de Servicio (DoS):** En algunos casos, la inyección de parámetros inesperados o la manipulación excesiva de los mismos puede llevar a un consumo excesivo de recursos del servidor, resultando en una denegación de servicio y afectando la disponibilidad de la aplicación.

## Mitigación
Mitigar los ataques de Polución de Parámetros HTTP (HPP) implica prácticas cuidadosas de codificación, validación estricta de parámetros y el uso de mecanismos de seguridad actualizados. Aquí hay algunas estrategias a considerar:

- **Aceptar solo parámetros conocidos:** Asegúrate de que tu aplicación solo acepte los parámetros esperados. Los parámetros no reconocidos deben tratarse como una anomalía, lo que resultaría en un error o en que la solicitud sea ignorada.  Si se espera que un parámetro sea un número, todo input no numérico debería ser rechazado.

- **Instancias únicas de parámetros:** Diseña tu aplicación para aceptar solo la primera instancia de un parámetro. Cualquier instancia adicional debe ser ignorada. Esto puede prevenir que un atacante use el mismo parámetro varias veces para explotar HPP.

- **Sanitización de inputs:** Implementa una rutina robusta de sanitización de inputs. Esto ayudará a eliminar cualquier cadena potencialmente dañina del input del usuario.

- **Uso de cabeceras de seguridad:** Considera usar cabeceras de seguridad como la Política de Seguridad de Contenido (CSP) para mitigar el riesgo de ataques de inyección de código.

- **Actualización de mecanismos de seguridad:** Actualiza regularmente firewalls de aplicaciones web, sistemas de detección de intrusiones y otras defensas de seguridad, además de frameworks y tecnologías que se estén usando. Los sistemas actualizados tienen más probabilidades de reconocer y bloquear nuevas formas de ataques.
 