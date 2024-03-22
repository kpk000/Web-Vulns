
#  Path Traversal

## Introducción

Este tipo de vulnerabilidad ocurre cuando una aplicación web construye la ruta a un archivo a mostrar a través de la ruta especificada en la URL (frontend). Esto lleva a que se puedan acceder a otros tipos de ficheros, lo que se conoce como **Local File Inclusion**.
Esta **falta de validación del _input_** puede ser explotada por un atacante para descargar información sensible, como datos personales y contraseñas.
Un ejemplo:
```url
http://web.com/archivo?ruta=ejemplo.txt
```

Si la aplicación web no valida correctamente la ruta, un atacante podría introducir rutas habituales de los servidores web para acceder a archivos sensibles.
```url
http://web.com/archivo?ruta=../../../../etc/passwd
```

Con `../` nos movemos hacia arriba por los directorios, cada expresión vuelve un directorio arriba.
En este caso el objetivo es llegar a la raíz, y desde ahí cargar la ruta del archivo `/etc/passwd`.
El archivo *passwd* es un archivo de lectura pública en el servidor, esto quiere decir que normalmente todos los usuarios del sistema pueden leerlo, se suele probar con este payload por esta misma razón, si intentásemos poner otro archivo y el usuario que ejecuta la petición (*www-data* normalmente) no tuviese permiso de lectura, el archivo no cargaría, pudiendo hacernos pensar que el payload del *Path Traversal* no funciona y cambiarlo.


## Causas comunes

Las causas comunes de la vulnerabilidad de Path Traversal se deben principalmente a fallos en la validación de entrada y manejo de acceso a archivos dentro de aplicaciones web. Estos fallos permiten a los atacantes manipular las rutas de archivos para acceder a directorios y archivos restringidos. 

## Pasos de explotación

Para explotar este tipo de vulnerabilidad, lo que debemos hacer es donde la aplicación web utiliza un input del usuario o del cliente para cargar un archivo y mostrarlo, por ejemplo como hemos mostrado anteriormente, en la URL.
A continuación podemos irnos a diccionarios de *payloads* e ir probando, a veces las aplicaciones web implementan WAF y mecanismos para validar caracteres en las peticiones, una "mitigación" muy común en PHP es el eliminar los carácteres "../" de la URL. 
Esto puede parecer seguro, pero con un simple truco podemos burlar el control:
`....//....//....//etc/passwd`
Al eliminar los caracteres `../` de nuestro input, si no lo hace recursivamente, nuestro payload cargado finalmente será:
`../../../etc/passwd`
Y podremos cargar el archivo.
Este es un ejemplo para *bypassear* el control, el atacante deberá investigar y probar para tratar de explotarlo.
Una metodología común es un ataque de fuerza bruta, por ejemplo utilizando *Burpsuite Intruder*, y filtrando por la longitud o el código de estado HTTP para ver ante que payload la respuesta ha cambiado.

## Implicaciones
La implicación del *Path Traversal* es un LFI directo, lo cual permite al atacante leer archivos del sistema, esto puede derivar en filtrado de información sensible, escalada de privilegios, o incluso derivarlo a una ejecución remota de comandos (RCE) a través de otros ataques como el envenenamiento de registros (Log Poisoning).

## Mitigación
Para mitigar las vulnerabilidades de Path Traversal y proteger las aplicaciones y sistemas web, es importante implementar una serie de estrategias y prácticas de seguridad. Aquí te detallo algunas de las más efectivas:


1. **Sanitización de Rutas de Archivos**: Aplica procesos de sanitización a las rutas de archivos para eliminar o neutralizar secuencias y caracteres especiales que podrían ser utilizados para navegar fuera de los directorios permitidos.

3. **Uso de Listas Blancas para Archivos y Rutas de Acceso**: Define y utiliza listas blancas de archivos y rutas de acceso permitidos para restringir el acceso solo a los recursos previstos y seguros.

4. **Implementación de Controles de Acceso**: Asegura que los controles de acceso estén correctamente configurados para limitar el acceso a archivos y directorios basándose en las necesidades y roles de los usuarios. Por ejemplo limitando solo la carga de archivos de una ruta : `servidor/archivosPublicos/nombreArchivoACargar`

5. **Uso de APIs de Manejo de Archivos Seguras**: Prefiere el uso de APIs de alto nivel para el manejo de archivos que automáticamente gestionen la seguridad de las rutas de acceso, evitando así las vulnerabilidades de Path Traversal.

6. **Aplicación de Políticas de Seguridad del Contenido (CSP)**: Implementa políticas de seguridad de contenido para restringir los recursos que pueden ser cargados o ejecutados en la aplicación web, lo que puede ayudar a mitigar el impacto de una vulnerabilidad de Path Traversal.