## Local File Inclusion (LFI)

## Introducción
Esta vulnerabilidad consiste en conseguir acceder a archivos de un servidor que no están predispuestos al público (son archivos sensibles y personales, no están en el directorio del servidor web por lo general ya que no están intencionados para ser mostrados).
Por ejemplo, si en una URL de una web vemos algo como esto:
`http://webVulnerable?archivo=pagina1`
Vemos como la URL recibe un *query param* con el que carga un archivo del servidor, este archivo no incluye la ruta completa ya que normalmente la petición ya lo incluye, por detrás se podría estar ejecutando algo asi:
```pseudocode
funcion mostrarArchivo():
   const nombre = URL.obtener("archivo");
   const archivo = /var/www/html/archivos/nombre
   devolver archivo;
```
Este es un ejemplo en pseudocódigo para mostrar como normalmente las rutas de los archivos están predefinidas.
Uno puede pensar que al estar las rutas predefinidas, en este caso al directorio `/var/www/html/archivos`, que solo se cargarán archivos del directorio y no es vulnerable a un LFI.
Sin embargo, usando otros tipos de vulnerabilidades como [Path Traversal](../Path%20Traversal/README), si la aplicación web no valida correctamente las peticiones de archivos, podemos movernos por los directorio y cargar archivos que no están predispuestos a ser mostrados, como el archivo en sistemas UNIX/Linux `/etc/passwd`. Este archivo suele ser el que se usa para probar esta vulnerabilidad, ya que suele ser de lectura pública, y como la petición se ejecutará con los permisos del usuario que ejecuta el proceso del servidor web (*www-data* comúnmente), así evitaremos falsos negativos, ya que si por ejemplo intentásemos mostrar un archivo para el cual el usuario que ejecuta la petición no tiene permisos, no se nos mostraría, pudiendo hacernos creer que el *payload* enviado es incorrecto, cuando el fallo está en los permisos del archivo y del usuario.

## Causas comunes

- La causa más común es cuando una aplicación web usa una ruta de una archivo en la URL y se fía del input del usuario, el usuario puede entonces modificar la ruta (por ejemplo con *Path Traversal*) y construir una nueva ruta para el archivo a cargar. Las rutas y los archivos deben de manejarse de forma controlada y sin fiarse del *input* del usuario.
- **Uso Inseguro de Funciones de Inclusión**: En PHP, funciones como `include()`, `require()`, `include_once()`, y `require_once()` pueden ser usadas para incluir archivos que contienen código PHP que será ejecutado por el servidor. Si la ruta del archivo incluido se construye a partir de entradas del usuario sin una limpieza adecuada, se puede explotar para incluir archivos arbitrarios.

## Pasos de explotación

Los pasos de explotación pueden variar dependiendo de las tecnologías de la aplicación web, pero la metodología suele ser similar. 
Primero se buscan rutas en la aplicación web que carguen archivos, buscamos parámetros de la URL que apunten a nombres de archivos.
```
http://webVulnerable?page=index.php
```
Por ejemplo en esta URL vemos como se carga un archivo PHP, ahora podemos probar diferentes payloads prediseñados que apuntan a directorios conocidos en servidores web:
```
http://webVulnerable?page=/etc/passwd
```
Si la web o la respuesta HTTP nos muestra el archivo, estamos de suerte, si no, revisar siempre el código fuente de la web por si acaso lo devuelve pero no se muestra en la plantilla por algún error como la longitud.
Si no nos muestra nada, tenemos que ir probando payloads, por ejemplo usando *Path Traversal* las veces suficientes como para asegurar que mediante `../` volvamos al directorio raiz.
```
http://webVulnerable?page=../../../../../../../etc/passwd
```
Lo ideal aquí es un ataque de diccionario, por ejemplo usando el *Intruder* , de BurpSuite, comparando la longitud de las respuestas podremos tratar de averiguar frente a que payload puede ser vulnerable a un LFI.

Normalmente no es tan sencillo, y tenemos que esmerarnos un poco más, la aplicación web puede tener "protecciones" que nos compliquen la tarea, por ejemplo puede haber una expresión regular que nos elimine los " ../ " de retroceder directorio para evitar que salgamos del directorio prediseñado, sin embargo se pueden probar diferentes tipos de *bypass*. Por ejemplo, si la expresión regular elimina los caracteres de forma no recursiva, podemos doblar los caracteres:
```
http://webVulnerable?page=....//....//....//....//....//....//....//etc/passwd
```
De esta forma al pasar la URL construida por la expresión regular, nos quitará los caracteres sobrantes y nuestra URL volverá a ser :
`http://webVulnerable?page=../../../../../../../etc/passwd`

Todo es ir probando, algunas aplicaciones web pueden concatenar *.php* al final de la ruta para que solo se puedan mostrar archivos *.php*, sin embargo podemos hacer uso del *Null Byte* : `%00`
Esta inyección esta presente en versiones de php antiguas (<5.34). Este *Null Byte* lo que hace es acabar con la cadena en su posición, por ejemplo:
```
http://webVulnerable?page=/etc/passwd
```
Se convierte en:
```
http://webVulnerable?page=/etc/passwd.php
```
Lo cual no nos mostrará nada porque no existe ese archivo php.
Sin embargo con el *Null Byte*:
```
http://webVulnerable?page=/etc/passwd%00
```
PHP interpreta que todo lo de detrás del *Null Byte* se debe eliminar, por lo tanto nuestra cadena acaba ahí, convirtiéndose en:
```
http://webVulnerable?page=/etc/passwd
```


## Implicaciones

Una vulnerabilidad de tipo **Local File Inclusion** (LFI), es algo serio y que no se debe tomar a la ligera, las implicaciones van desde filtración de información sensible (credenciales,tokens de acceso...) hasta un la ejecución de código remoto (RCE), lo que puede llevar al compromiso total del servidor.
Por ejemplo si un servidor interpreta PHP, un atacante puede hacer una petición maliciosa al servidor con código PHP malicioso en una de sus cabeceras, luego puede acceder a los registros (logs) del servidor web, al cargar los registros (`/var/log/apache2/access.log` en apache) con el código PHP malicioso, el servidor lo ejecutará, esto se conoce como *Log Poisoning*, y es la forma más común de ampliar/derivar un LFI a un RCE.

## Mitigación

- No se debe permitir que la ruta del archivo se pueda modificar directamente.
- Para la asignación de ID, guardar las rutas de los archivos en una base de datos segura y proporcionar un ID para cada uno, de esta manera los usuarios sólo podrían visualizar su ID sin ver o alterar la ruta.
- Es importante también montar el servidor con el mínimo privilegio posible, limitando la posibilidad de acceso a archivos del servidor dentro de su propia carpeta.
- Si necesitamos una concatenación dinámica de rutas, debemos asegurarnos de aceptar sólo los caracteres requeridos como "a-Z o 0-9" y no permitir ".." o "/" o "%00" (byte nulo) o cualquier otro carácter inesperado similar.
- Utilizar una lista blanca de archivos permitidos.
- Si se desea hacer una protección mediante programación en lugar de tratar de controlar mediante permisos en el servidor, hay que tener en cuenta que las rutas a ficheros se pueden escribir de dos maneras:  
    -Directa: escribimos la ruta donde se encuentra el fichero directamente. Se debería eliminar los caracteres “\” o “/” de los datos enviados por los usuarios.  
    -Relativa: subir hacia directorios superiores mediante el uso de “..\” o “../”. Lo podríamos evitar excluyendo, además de lo anterior, los puntos. Que esto sería otro tipo de vulnerabilidad Path traversal.
Fuente de las mitigaciones: (https://blog.isecauditors.com/2022/10/lfi-una-vulnerabilidad-que-no-se-puede-subestimar.html)

Además de:
- Utiliza funciones de manejo de archivos que no permitan la inclusión de archivos externos o el acceso a rutas relativas que puedan ser manipuladas. Evita el uso de `include`, `require`, `include_once`, y `require_once` con variables que pueden ser modificadas por el usuario.