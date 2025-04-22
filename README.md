# cifrado_archivos
Cifrado de archivos txt en Python utilizando criptografía híbrida.

La criptografía híbrida es el uso de diferentes algortimos criptográficos para poder lograr diferentes propiedades de la ciberseguridad de los activos.

Los algortimos utilizados son:

## AES

Se utiliza el algoritmo AES en su versión de 128 bits, generando una clave y un vector de entrada aleatorios de este tamaño para poder cifrar la información. Se utiliza el modo de cifrado en CBC que es uno de los modos más seguros de cifrar utilizando AES. Este algoritmo nos permite ofrecer integridad, debido a que si la información es modificada, el archivo no se descifrará correctamente y confidencialidad parcial debido a que asegura que solo quien conozca el vector de entrada y la llave utilizada, podrá descifrar el archivo correctamente.

## RSA

Se utiliza el algoritmo de RSA con claves privadas de 2048 bits generadas de manera aleatoria. Estas son útiles para poder cifrar la llave utilizada en el algoritmo de AES, de esta forma, no se puede obtener de manera directa la llave, haciendo complicado que se pueda obtener la información en crudo. Este algoritmo nos ofrece confidencialidad debido a que se tiene una clave privada que cada usuario puede resguardar para poder cifrar y descifrar la llave utilizada para cifrar la información.

## SHA

Se utiliza el algoritmo de SHA en su versión de 256 bits el cual nos permite crear un digesto de la información para poder verificar si la información fue modificada, además de permitirnos poder firmar el documento o verificar la firma de este. Este algoritmo nos permite ofrecer Verificación y No Repudio debido a que este se firma con una llave privada, haciendo que al momento de hacer una verificación correcta, se asegura que la persona que la firmó, es quien dice ser y no puede rechazar esto, a menos que su llave privada haya sido expuesta. Además ofrece integridad debido a que se puede verificar si el contenido del archivo fue modificado, ya que se utilizan funciones que si un bit es cambiado, el digesto se modifica en su totalidad.


