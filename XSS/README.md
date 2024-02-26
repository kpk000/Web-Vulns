# XSS

## Introducción

Esta vulnerabilidad consiste en que el atacante logra inyectar un script malicioso en el cliente (frontend) del sitio web, el navegador no puede diferenciar entre un script légitimo y uno malicioso, de este modo el script se ejecuta con los mismos privilegios (depende del CSP configurado) que los demás de scripts legítimos.
Esto le  da poder para modificar el contenido, derivar a ataques CSRF, Cookie Hijacking (debido al poder del script de acceder a las cookies)

## Causas Comunes

Las causas comunes suelen ser:
- Falta de sanitización de las entradas: Confiar en el input del usuario y no validar la entrada antes de procesarla.
- Falta de sanitización de outputs: Cuando no se validan los datos que se envían desde el servidor a los navegadores de los usuarios.
- Cuando la web utiliza datos proporcionados por la URL sin sanitización (suele acontecer un **Reflected XSS**)
- Mala implemetación de una CSP (Política de Seguridad de Contenido), que pueda restringir que recursos y scripts puede cargar el navegador.
- Usar bibliotecas, templates, plugins ... y/o componentes vulnerables a este tipo de ataque.


## Tipos

- **XSS Reflejado**
     - Este tipo ocurre cuando un sitio web recibe contenido a través de una solicitud HTTP/URL y los incluye en su respuesta sin manejarlos.
      Ejemplo:
      Supongamos que una página insegura utiliza un parámetro en su URL para reflejarlo en su contenido sin validarlo.
      ``` https://tienda.com/buscar?producto=lavadora ```
      La tienda espera siempre recibir una cadena String, para representarla en su contenido, por ejemplo de esta manera:
      `<p>Resultados para: lavadora</p>`
      Sin embargo se podría construir un hipervínculo malicioso con el siguiente payload:
     `https://tienda/buscar?producto=<script>/*SCRIPT MALICIOSO AQUI*/</script>`
     Si el atacante consigue que un usuario víctima de *click* en el enlace, la página cargará el script y se ejecutará en el navegador de la víctima, arrastrando su sesión.
     Este tipo de ataque se podría derivar a *CSRF*, *Cookie Hijacking*...
     
- **XSS Almacenado**
     Este tipo de vulnerabilidad de XSS es cuando el script malicioso obtiene persistencia, es decir, el servidor lo incluirá en respuestas HTTP posteriores (cada vez que se renderice esa sección de la página).
     Un ejemplo rápido es cuando un blog no valida los comentarios de un post, un atacante podría aprovecharse de una mala implementación para colar su script.
     `<p>Comentario</p>`
     Al igual que el ejemplo anterior, el atacante podría colocar una etiqueta `<script>` la cual el navegador ejecutará en todos los usuarios que vean ese comentario. 
     A diferencia del *XSS Reflejado*, este ataque tiene por lo usual un *scope* de víctimas mucho más amplio, ya que con colar el script, se ejecutará en los navegadores de los usuarios automáticamente cuando por ejemplo vean el comentario.
     Además si el *XSS Almacendo* ha sido depositado en una pantalla que requiera estar loggeado, esto garantizará al atacante que solo usuarios loggeados lo ejecutarán, al contrario que los *XSS Reflejados*, que puede que el usuario víctima no este loggeado al ejecutarlo y reducir significativamente su impacto.
     
- **XSS Basado en el DOM**
   Para entender esta vulnerabilidad, hay que tener un conocimiento básico sobre el DOM, el DOM (Document Object Model) es una interfaz de programación (API) que permite modificar el frontend y el código fuente de una aplicación web. El DOM es básicamente la estructura que envuelve todo el código fuente de una web, permite leer,acceder y modificar este código fuente (estructura de árbol de código HTML y XML). 
   Usando una mala gestión del DOM, los atacantes consiguen incluir etiquetas y scripts maliciosos en el cliente directamente, a diferencia de el XSS reflejado o almacenado, cuyo principal vector de ataque es el servidor web y su forma de manejar y responder a las peticiones HTTP.
   El navegador procesa y ejecuta el script como si fuese una parte legítima de la web, importante recalcar que el script malicioso nunca llega al servidor, se carga directamente en el cliente a través del DOM y el navegador lo ejecuta.

## Pasos de explotación

Algunos pasos para descubrir este tipo de vulnerabilidades son:
- Probar cada input de entrada: Ir probando cada entrada y parámetro en las solicitudes HTTP y en las secciones donde la web utilice el input del usuario y lo represente. A veces podemos encontrarnos con *regex* que pueden complicar un poco más la explotación, los pasos serían tratar de romper o probar por fuerza bruta la regex o tratar de mandar los datos directamente al servidor para ver si la validación esta únicamente implementada en el *frontend*.
- **Envíe valores alfanuméricos aleatorios:** Para cada punto de entrada, envíe un valor aleatorio único y determine si el valor se refleja en la respuesta.
- **Testear payloads hechos**: Una forma efectiva es testear *payloads* realizados para diferentes contextos hasta que alguno se refleje en la respuesta sin modificaciones, tras este paso, queda comprobar si el *payload* se ejecuta también en el navegador (Puede haber una CSP que lo bloquee).

## Implicaciones

Las implicaciones y derivaciones de una vulnerabilidad XSS (Cross-Site Scripting) son variadas y pueden ser de gran alcance, afectando tanto a usuarios individuales como a organizaciones enteras.
1. **Robo de Cookies (Cookie Hijacking):** Una de las explotaciones más comunes del XSS es el robo de cookies de sesión. Esto puede permitir a un atacante secuestrar sesiones de usuario, accediendo así a cuentas protegidas sin necesidad de una contraseña.
2. **Robo de Información Personal:** Los scripts maliciosos pueden ser diseñados para capturar cualquier tipo de información que el usuario ingrese en formularios web, incluyendo datos personales, financieros, y credenciales de acceso. Por ejemplo un script podría añadir un *eventListener* en un input con el atributo `type=password` para enviar cada tecla pulsada al servidor del atacante, actuando así como un *keylogger*:
3. **Propagación de Malware:** Los atacantes pueden utilizar el XSS para distribuir malware, haciendo que los usuarios descarguen e instalen software malicioso sin su conocimiento.
4. **Phishing:** El XSS puede ser utilizado para redirigir a los usuarios a sitios de phishing o para modificar el contenido de la página web, haciendo que los ataques de phishing sean más creíbles (similar a un *Open Redirect*).
5. **Ataques contra otros usuarios:** A través del XSS, un atacante puede realizar acciones en nombre de otros usuarios, como publicar contenido ofensivo o realizar transacciones fraudulentas.
6. **Daño a la Reputación:** Las vulnerabilidades XSS pueden dañar la reputación de una organización, ya que indican debilidades en la seguridad del sitio. Esto puede llevar a una pérdida de confianza por parte de los usuarios y clientes.
8. **Daño a la Seguridad Interna:** En algunos casos, el XSS puede ser utilizado como punto de entrada para ataques más sofisticados contra la infraestructura interna de una organización, posiblemente dando lugar a una escalada de privilegios o al acceso no autorizado a datos sensibles.

## Mitigación

- La mitigación más fácil es **utilizar frameworks** modernos y actualizados para el desarrollo de una aplicación web, ya que estos normalmente ya incluyen ciertas protecciones **básicas** contra XSS.
  Sin embargo, si los frameworks se utilizan de manera insegura y con malas prácticas, podremos desencadenar ataques XSS, es importante siempre seguir las buenas prácticas de la documentación de cada framework.
- Otro punto es la **validación y sanitización de todas las entradas** (**perfect injection resistance**), cualquier entrada que no pase por este proceso de limpieza, puede ser un punto débil.
- **Manejar correctamente el procesamiento de la entrada**, es decir, evitar que el navegador pueda procesar código introducido, y que lo procese como simple texto, por ejemplo usando la propiedad `.textContent` de HTML en lugar del peligroso `.innerHTML`.
- También es buena práctica usar *HTML Entity Encode* :
```html
&    &amp;
<    &lt;
>    &gt;
"    &quot;
'    &#x27;
```
- **Implementar una fuerte CSP**, la CSP permite a los administradores de sitios web especificar qué fuentes de contenido son confiables, limitando la capacidad de un atacante para inyectar contenido malicioso. Aunque una CSP no es una solución completa, puede ser una capa adicional de defensa efectiva.
- **Atributos de Cookies Seguras:** Configura las cookies con atributos como `HttpOnly` y `Secure`. `HttpOnly` impide que las cookies sean accesibles a través de scripts del lado del cliente, lo que reduce el riesgo de robo de cookies a través de XSS. El atributo `Secure` asegura que las cookies solo se envíen a través de conexiones HTTPS.