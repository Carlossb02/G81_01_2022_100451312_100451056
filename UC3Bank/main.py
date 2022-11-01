# UC3Bank
import json
import os
import getpass
import re
import exrex
import datetime
from patterns import *
from usuario import Usuario
from cuenta import Cuenta
from kdf import *
from PBKDF2 import *
from Fernet import *


##IMPORTANTE: la contraseña es visible en los JSON porque todavía no se han aplicado los algoritmos de cifrado,
##en la versión final, no se almacenará la contraseña en claro.

def home():
    print("\033[1m\033[96mUC3Bank")
    print("\n")
    print("\033[93m--------------------------------")
    print("(1) Iniciar sesión")
    print("(2) Registrarse")
    print("\033[93m--------------------------------")
    sel=input("\n\033[94mElija su operación: ")
    if sel=="1":
        iniciar_sesion()
    elif sel=="2":
        registrarse()
    else:
        print("\033[91mError: Esa opción es incorrecta\n")
        home()

######################################################################################################################
######################################################################################################################
# GESTIÓN DE USUARIOS
######################################################################################################################
######################################################################################################################

def iniciar_sesion():
    """"Esta función comprueba que el usuario existe, verifica la contraseña con algoritmos de descifrado y da
    acceso al usuario al sistema si la autenticación es correcta"""

    user=input("\n\033[94mIntroduzca su nombre de usuario: ")
    path="Database/Usuarios/"+user+".json"

    #Verificamos si el usuario está registrado
    if not os.path.exists(path):
        print("\033[91mError: Ese nombre de usuario no existe\n")
        home()

    #Una vez comprobado que el usuario existe, obtenemos sus datos y su contraseña
    datos_user=obtener_datos(path)
    #password = getpass.getpass("Introduzca su constraseña: ")
    ##Se iba a añadir esta función para no hacer la contraseña visible mientras la introduce el usuario, pero no es compatible con la terminal de windows


    password=input("\033[94mIntroduzca su contraseña: ")

    #Si la contraseña es correcta, se accede a la sección de operaciones
    #if password!=datos_user["Password"]:
    #    print("\033[91mError: Su contraseña no es correcta\n")
    #    home()

    try:
        verify(password,datos_user["Password"].encode('latin-1'), datos_user["Salt"].encode('latin-1'))
    except:
        print("\033[91mError: Su contraseña no es correcta\n")
        home()
    print("\n\033[94m\033[4mBienvenido/a\033[92m\033[24m", user)
    usuario=Usuario(datos_user["Usuario"], datos_user["Password"], datos_user["Salt"], path, datos_user["Cuentas"])
    cuentas(usuario)


def registrarse():
    """Esta función comprueba que el nombre de usuario a registrar no exista, pide al usuario crear
    una contraseña y posteriormente almacena el token y el salt en un .json"""


    user = input("\n\033[94mIntroduzca un nombre de usuario: ")

    ##Al principio, se iba a utilizar el mismo archivo para todos los datos,
    # pero dar acceso a información privada (saldo o número de cuenta) sin autenticarse es un fallo grave de seguridad

    path="Database/Usuarios/"+user+".json"

    #Verificamos que el usuario no exista
    if os.path.exists(path):
        print("\033[91mError: Ese nombre de usuario ya está registrado\n")
        home()

    #Si el usuario no existe, se procede a su registro

    password=input("\033[94mIntroduzca su contraseña (Recuerde que debe contener mayúsculas, minúsculas y números, con al menos 6 caracteres): ")

    #Se comprueba que la contraseña cumpla con las condiciones
    if not re.match(password_pattern, password):
        print("\033[91mError: Recuerde que la contraseña debe contener mayúsculas,\nminúsculas y números, con al menos 6 caracteres\n")
        registrarse()

    key=derive(password)

    user_data_dict={"Usuario": user, "Password": key[0], "Salt": key[1], "Cuentas": []}

    #Se registra al usuario
    with open(path, "w") as file:
        json.dump(user_data_dict, file)

    print("\033[92m¡Usuario registrado con éxito! \n")

    home()

######################################################################################################################
######################################################################################################################
# GESTIÓN DE CUENTAS
######################################################################################################################
######################################################################################################################

def cuentas(usuario):
    print("\n")
    print("\033[93m--------------------------------")
    print("(1) Crear cuenta")
    print("(2) Seleccionar cuenta")
    print("(3) Cerrar sesión")
    print("\033[93m--------------------------------")
    sel=input("\n\033[94mElija su operación: ")

    if sel=='1':
        crear_cuenta(usuario)
    elif sel=='2':
        seleccionar_cuenta(usuario)
    elif sel=='3':
        del(usuario)
        print("\033[92mSe ha cerrado la sesión, hasta pronto...\n")
        home()
    else:
        print("\033[91mError: Esa opción es incorrecta\n")
        cuentas(usuario)


def crear_cuenta(usuario):
    """Función para crear una nueva cuenta"""

    #Restringimos a 4 cuentas como máximo por usuario
    if len(usuario.cuentas)>=4:
        print("\033[91mError: Número máximo de cuentas alcanzado\n")
        cuentas(usuario)

    numero_cuenta=exrex.getone(r'ES[A-Z0-9]{6}')
    #path_cuentas="Database/Cuentas/"+usuario.nombre+"_"+numero_cuenta+".json"
    path_cuentas = "Database/Cuentas/" + numero_cuenta + ".json"

    #Comprobamos que ese número de cuenta no haya sido asociado a otro cliente
    #Es muy improbable, pero posible que esto suceda y sería un grave fallo de seguridad
    #por lo que en caso de que esto se dé, repetimos el proceso para generar una nueva.
    if os.path.exists(path_cuentas):
        crear_cuenta(usuario)

    pin=str(input("\033[94mIntroduzca un pin (4 números) para proteger su cuenta: "))

    #Se comprueba que el pin cumpla con las condiciones
    if not re.match(pin_pattern, pin):
        print("\033[91mError: Recuerde el pin debe contener exactamente 4 números")
        crear_cuenta(usuario)

    pin=pbkdf2_derive(pin)

    #encriptamos el saldo
    f=fernet_encrypt(str(0))


    cuenta_nueva={"Propietario": usuario.nombre, "Numero de cuenta": numero_cuenta, "Pin": pin[0], "Salt": pin[1], "Saldo":f[0], "Path":path_cuentas, "Transferencias":[]}



    with open(path_cuentas, "w") as file:
        json.dump(cuenta_nueva, file)

    #Buscamos el diccionario de symetric keys
    lista_keys=obtener_datos("Database/System/symetric_keys.json")
    #Añadimos la nueva key (EN SITUACIÓN REAL, NUNCA SE DEBE ALMACENAR EN CLARO)
    lista_keys[numero_cuenta]=f[1]
    #Guardamos el diccionario de keys
    with open("Database/System/symetric_keys.json", "w+") as file:
        json.dump(lista_keys, file)


    usuario.cuentas.append(numero_cuenta)
    print("\033[92m¡Cuenta registrado con éxito! Su número de cuenta es:", numero_cuenta)
    guardar_datos_usuario(usuario)
    cuentas(usuario)


def seleccionar_cuenta(usuario):
    """Función para seleccionar la cuenta con la que se realizarán las operaciones"""

    #Comprobamos que haya cuentas creadas para el usuario
    if len(usuario.cuentas)<=0:
        print("\033[91mError: Este usuario no tiene ninguna cuenta a su nombre\n")
        cuentas(usuario)

    print("\n")
    print("\033[93m--------------------------------")
    index=1

    #Imprimimos la lista de cuentas del usuario
    for i in usuario.cuentas:
        print("("+str(index)+") "+i)
        index+=1
    print("\033[93m--------------------------------")
    sel=input("\n\033[94mElija su operación: ")

    try:
        sel=int(sel)
    except:
        print("\033[91mError: Esa opción es incorrecta\n")
        cuentas(usuario)

    if sel>index-1 or sel<1:
        print("\033[91mError: Esa opción es incorrecta\n")
        cuentas(usuario)

    print("\033[92mCuenta "+usuario.cuentas[sel-1]+" seleccionada")

    datos_cuenta=obtener_datos("Database/Cuentas/"+usuario.cuentas[sel-1]+".json")
    keys=obtener_datos("Database/System/symetric_keys.json")
    key_user=keys[datos_cuenta["Numero de cuenta"]]
    saldo_user=fernet_decrypt(datos_cuenta["Saldo"], key_user)


    cuenta_usuario=Cuenta(datos_cuenta["Propietario"], datos_cuenta["Numero de cuenta"], datos_cuenta["Pin"], datos_cuenta["Salt"], float(saldo_user), datos_cuenta["Path"], datos_cuenta["Transferencias"])

    pin = input("\n\033[94mIntroduzca el pin de su cuenta bancaria (Escriba '0' para volver): ")
    if pin == "0":
        cuentas(usuario)

    try:
        pbkdf2_verify(pin, cuenta_usuario.pin.encode('latin-1'), cuenta_usuario.salt.encode('latin-1'))
    except:
        print("\033[91mError: Su pin no es correcto\n")
        cuentas(usuario)
    operaciones(usuario, cuenta_usuario)

def transferencias_recibidas(cuenta):
    """Función para generar una notificación cuando se recibe una transferencia"""

    for i in cuenta.transferencias:
        indice=cuenta.transferencias.index(i)
        cuenta.transferencias.pop(indice)
        data=obtener_datos("Database/Transferencias/"+i+".json")
        user_data=obtener_datos(cuenta.path)
        print("\033[91m⚠ \033[92m¡Ha recibido una transferencia de", data["Remitente"], "("+str(data["Cantidad"])+"€)!")

        user_data_dict = {"Propietario": cuenta.propietario, "Numero de cuenta": cuenta.cuenta, "Pin": cuenta.pin, "Salt": cuenta.salt,
                          "Saldo": user_data["Saldo"], "Path": cuenta.path, "Transferencias": cuenta.transferencias}
        with open(cuenta.path, "w") as file:
            json.dump(user_data_dict, file)


######################################################################################################################
######################################################################################################################
# GESTIÓN DE OPERACIONES
######################################################################################################################
######################################################################################################################


def operaciones(usuario, cuenta):
    print("\n")
    transferencias_recibidas(cuenta)
    print("\033[93m--------------------------------")
    print("(1) Consultar saldo")
    print("(2) Retirar dinero")
    print("(3) Ingresar dinero")
    print("(4) Realizar una transferencia")
    print("(5) Cambiar de cuenta")
    print("(6) Borrar cuenta")
    print("(7) Cerrar sesión")
    print("\033[93m--------------------------------")
    sel=input("\n\033[94mElija su operación: ")

    if sel=="1":
        dinero_saldo(usuario, cuenta)
    elif sel=="2":
        dinero_retirar(usuario, cuenta)
    elif sel=="3":
        dinero_ingresar(usuario, cuenta)
    elif sel=="4":
        dinero_transferencia(usuario, cuenta)
    elif sel=="5":
        del(cuenta)
        cuentas(usuario)
    elif sel=="6":
        borrar_cuenta(usuario, cuenta)
    elif sel=="7":
        del(cuenta)
        del(usuario)
        print("\033[92mSe ha cerrado la sesión, hasta pronto...\n")
        home()
    else:
        print("\033[91mError: Esa opción es incorrecta\n")
        operaciones(usuario, cuenta)

def dinero_saldo(usuario, cuenta):
    print("\033[92mSu saldo es: ", cuenta.saldo,"€")
    operaciones(usuario, cuenta)

def dinero_retirar(usuario, cuenta):

    pin= input("\n\033[94mIntroduzca el pin de su cuenta bancaria (Escriba '0' para volver): ")
    if pin=="0":
        operaciones(usuario, cuenta)

    try:
        pbkdf2_verify(pin, cuenta.pin.encode('latin-1'), cuenta.salt.encode('latin-1'))
    except:
        print("\033[91mError: Su pin no es correcto\n")
        cuentas(usuario)

    ret= input("\n\033[94m¿Cuánto dinero quiere retirar?: ")
    try:
        ret=float(ret)
    except:
        print("\033[91mError: Debe introducir un número, los decimales se indican con '.'\n")
        operaciones(usuario, cuenta)

    if ret <= 0:
        print("\033[91mError: No puede retirar dinero negativo")
        dinero_saldo(usuario, cuenta)

    if ret>cuenta.saldo:
        print("\033[91mError: No hay fondos disponibles en su cuenta")
        dinero_saldo(usuario, cuenta)

    cuenta.saldo-=ret
    print("\033[92m¡Retirada realizada con éxito! \nNuevo saldo:", cuenta.saldo, "€")
    guardar_datos_cuenta(usuario, cuenta)

def dinero_ingresar(usuario, cuenta):

    try:
        ret=float(input("\n\033[94m¿Cuánto dinero quiere ingresar?: "))
        if ret <= 0:
            print("\033[91mError: No puede transferir dinero negativo")
            dinero_saldo(usuario, cuenta)
        print(cuenta.saldo)
        cuenta.saldo+=ret
    except:
        print("\033[91mError: Debe introducir un número, los decimales se indican con '.'\n")
        operaciones(usuario, cuenta)

    print("\033[92m¡Ingreso realizado con éxito! \nNuevo saldo:", cuenta.saldo,"€")
    guardar_datos_cuenta(usuario, cuenta)

def dinero_transferencia(usuario, cuenta):

    pin = input("\n\033[94mIntroduzca el pin de su cuenta bancaria (Escriba '0' para volver): ")
    if pin == "0":
        operaciones(usuario, cuenta)

    try:
        pbkdf2_verify(pin, cuenta.pin.encode('latin-1'), cuenta.salt.encode('latin-1'))
    except:
        print("\033[91mError: Su pin no es correcto\n")
        cuentas(usuario)

    cuenta_ingreso = input("\n\033[94m¿A qué cuenta desea transferir el dinero (Recuerde respetar las mayúsculas)?: ")

    if not os.path.exists("Database/Cuentas/"+cuenta_ingreso+".json"):
        print("\033[91mError: Esa cuenta no existe\n")
        operaciones(usuario, cuenta)

    if cuenta_ingreso==cuenta.cuenta:
        print("\033[91mError: No puede hacer una transferencia a su cuenta seleccionada\n")
        operaciones(usuario, cuenta)

    ret = input("\n\033[94m¿Cuánto dinero quiere transferir?: ")
    try:
        ret=float(ret)
    except:
        print("\033[91mError: Debe introducir un número, los decimales se indican con '.'\n")
        operaciones(usuario, cuenta)

    if ret>cuenta.saldo:
        print("\033[91mError: No hay fondos disponibles en su cuenta")
        dinero_saldo(usuario, cuenta)

    if ret<=0:
        print("\033[91mError: No puede transferir dinero negativo")
        dinero_saldo(usuario, cuenta)

    cuenta.saldo-=ret

    #Obtenemos datos de la cuenta a la que realizar el ingreso
    datos_cuenta=obtener_datos("Database/Cuentas/"+cuenta_ingreso+".json")

    keys=obtener_datos("Database/System/symetric_keys.json")
    key_user=keys[datos_cuenta["Numero de cuenta"]]
    saldo_user=fernet_decrypt(datos_cuenta["Saldo"], key_user)


    cuenta_destino=Cuenta(datos_cuenta["Propietario"], datos_cuenta["Numero de cuenta"], datos_cuenta["Pin"], datos_cuenta["Salt"], float(saldo_user), datos_cuenta["Path"], datos_cuenta["Transferencias"])
    cuenta_destino.saldo+=ret


    #Guardamos el recibo de la transferencia

    numero_transferencia=exrex.getone(r'TR[a-zA-Z0-9]{6}'+str(datetime.datetime.utcnow().timestamp()))
    transferencia_datos={"Remitente": cuenta.propietario, "Destinatario": cuenta_destino.propietario, "Cantidad":ret, "Fecha":str(datetime.datetime.utcnow()), "Path":"Database/Transferencias/"+numero_transferencia+".json"}
    cuenta_destino.transferencias.append(numero_transferencia)

    with open(transferencia_datos["Path"],"w") as file:
        json.dump(transferencia_datos, file)

    print("\033[92m¡Transferencia realizada con éxito!")

    guardar_datos_cuenta_transferencia(usuario, cuenta, cuenta_destino)

def borrar_cuenta(usuario, cuenta):
        pin = input("\n\033[94mIntroduzca el pin de su cuenta bancaria (Escriba '0' para volver): ")
        if pin == "0":
            operaciones(usuario, cuenta)

        try:
            pbkdf2_verify(pin, cuenta.pin.encode('latin-1'), cuenta.salt.encode('latin-1'))
        except:
            print("\033[91mError: Su pin no es correcto\n")
            cuentas(usuario)

        if int(cuenta.saldo)>0:
            print("\033[91mError: No puede borrar una cuenta con saldo disponible")
            operaciones(usuario, cuenta)

        print("\n")
        print("\033[93m--------------------------------")
        print("(1) Cancelar")
        print("(2) Borrar cuenta")
        print("\033[93m--------------------------------")

        sel=input("\n\033[91m⚠\033[94m ¿Está seguro de que quiere borrar la cuenta "+cuenta.cuenta+"?: ")
        if sel == '1':
            operaciones(usuario, cuenta)
        elif sel == '2':
            usuario.cuentas.pop(usuario.cuentas.index(cuenta.cuenta))
            os.remove(cuenta.path)
            guardar_datos_usuario(usuario)
            print("\033[92m¡Cuenta eliminada con éxito!")
            cuentas(usuario)
        else:
            print("\033[91mError: Esa opción es incorrecta\n")
            cuentas(usuario)

######################################################################################################################
######################################################################################################################
# GESTIÓN DE DATOS EN LOS JSON
######################################################################################################################
######################################################################################################################

def obtener_datos(path):
    with open(path, "r") as file:

        datos=json.load(file)
    return datos

def guardar_datos_usuario(usuario):
    user_data_dict={"Usuario": usuario.nombre, "Password": usuario.password, "Salt": usuario.salt, "Path": usuario.path, "Cuentas": usuario.cuentas}
    with open(usuario.path, "w") as file:
        json.dump(user_data_dict, file)

def guardar_datos_cuenta(usuario, cuenta):
    saldo=fernet_encrypt(str(cuenta.saldo))
    #Buscamos el diccionario de symetric keys
    lista_keys=obtener_datos("Database/System/symetric_keys.json")
    #Añadimos la nueva key (EN SITUACIÓN REAL, NUNCA SE DEBE ALMACENAR EN CLARO)
    lista_keys[cuenta.cuenta]=saldo[1]
    #Guardamos el diccionario de keys
    with open("Database/System/symetric_keys.json", "w+") as file:
        json.dump(lista_keys, file)

    user_data_dict={"Propietario": cuenta.propietario, "Numero de cuenta": cuenta.cuenta, "Pin": cuenta.pin, "Salt":cuenta.salt, "Saldo":saldo[0], "Path":cuenta.path, "Transferencias":cuenta.transferencias}
    with open(cuenta.path, "w") as file:
        json.dump(user_data_dict, file)
    operaciones(usuario, cuenta)

def guardar_datos_cuenta_transferencia(usuario, cuenta, cuentadest):

    #Ciframos saldo usuario que transfiere
    saldo_tr=fernet_encrypt(str(cuenta.saldo))
    #Buscamos el diccionario de symetric keys
    lista_keys=obtener_datos("Database/System/symetric_keys.json")
    #Añadimos la nueva key (EN SITUACIÓN REAL, NUNCA SE DEBE ALMACENAR EN CLARO)
    lista_keys[cuenta.cuenta]=saldo_tr[1]
    with open("Database/System/symetric_keys.json", "w+") as file:
        json.dump(lista_keys, file)

    #Ciframos saldo usuario que recibe
    saldo_dest=fernet_encrypt(str(cuentadest.saldo))
    print(saldo_dest[0])
    #Buscamos el diccionario de symetric keys
    lista_keys=obtener_datos("Database/System/symetric_keys.json")
    #Añadimos la nueva key (EN SITUACIÓN REAL, NUNCA SE DEBE ALMACENAR EN CLARO)
    lista_keys[cuentadest.cuenta]=saldo_dest[1]
    with open("Database/System/symetric_keys.json", "w+") as file:
        json.dump(lista_keys, file)

    user_data_dict={"Propietario": cuenta.propietario, "Numero de cuenta": cuenta.cuenta, "Pin": cuenta.pin, "Salt":cuenta.salt, "Saldo":saldo_tr[0], "Path":cuenta.path, "Transferencias":cuenta.transferencias}
    dest_data_dict={"Propietario": cuentadest.propietario, "Numero de cuenta": cuentadest.cuenta, "Pin": cuentadest.pin, "Salt":cuentadest.salt, "Saldo":saldo_dest[0], "Path":cuentadest.path, "Transferencias":cuentadest.transferencias}



    with open(cuenta.path, "w") as file:
        json.dump(user_data_dict, file)
    with open(cuentadest.path, "w") as file:
        json.dump(dest_data_dict, file)
    operaciones(usuario, cuenta)

home()


