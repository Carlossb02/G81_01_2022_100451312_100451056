# UC3Bank
import json
import os
import getpass
import re
import exrex
import datetime
from patterns import *
from usuario import Usuario
from empresas import *
from cuenta import Cuenta
from kdf import *
from PBKDF2 import *
from Fernet import *
from RSA import *
from CSR import *
from CERT import *


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

    #if datos_user["Status"]=="Block" or datos_user["Status"]=="CBlock":
    #    print("\033[91mError: Su cuenta se encuentra bloqueada, contacte con un administrador.\n")
    #    home()


    #password = getpass.getpass("Introduzca su constraseña: ")
    ##Se iba a añadir esta función para no hacer la contraseña visible mientras la introduce el usuario, pero no es compatible con la terminal de windows


    password=input("\033[94mIntroduzca su contraseña: ")

    try:
        verify(password,datos_user["Password"].encode('latin-1'), datos_user["Salt"].encode('latin-1'))
    except:
        print("\033[91mError: Su contraseña no es correcta\n")

        ##Sistema de bloqueo de cuentas tras introducir tres veces mal la contraseña, desactivado debido a que cualquira
        ##que conozca tu nombre de usuario (que es público), puede bloquear la cuenta y denegarte el servicio.
        #if datos_user["Status"]=="User":
        #    datos_user["Status"]="Warning1"
        #elif datos_user["Status"]=="Warning1":
        #    datos_user["Status"]="Warning2"
        #elif datos_user["Status"]=="Warning1":
        #    datos_user["Status"]="Warning2"
        #elif datos_user["Status"]=="Warning2":
        #    datos_user["Status"] = "Block"
        #elif datos_user["Status"]=="Company":
        #    datos_user["Status"]="CWarning1"
        #elif datos_user["Status"]=="CWarning1":
        #    datos_user["Status"]="CWarning2"
        #elif datos_user["Status"]=="CWarning1":
        #    datos_user["Status"]="CWarning2"
        #elif datos_user["Status"]=="CWarning2":
        #    datos_user["Status"] = "CBlock"
        #guardar_datos_status(datos_user)
        home()

    # Generamos las claves pública y privada aquí para que los usuarios antiguos tambíen tengan claves
    # Tomamos esta decisión ya que consideramos que comprobar la existencia de dos directorios cada vez que se inicia
    # sesión no es costoso y nos ahorra fallos de compatibilidad con versiones anteriores de la aplicación
    rsa_genkeys(user, password)

    #Comprobamos el estado del usuario antes de permitirle acceder
    if datos_user["Status"]=="Verification":
        if os.path.exists("Database/Certs/nuevoscerts/"+datos_user["Usuario"]+".pem"):
            datos_user["Status"]="Company"
            datos_user["Path"]=path
            guardar_datos_status(datos_user)
        else:
            print("\033[91mError: Su cuenta de empresa está pendiente de verificación, pruebe de nuevo más tarde.\n")
            home()


    print("\n\033[94m\033[4mBienvenido/a\033[92m\033[24m", user)

    #if datos_user["Status"]=="Block" or datos_user["Status"]=="Warning1" or datos_user["Status"]=="Warning2":
    #    datos_user["Status"]="User"
    #    guardar_datos_status(datos_user)
    #elif datos_user["Status"]=="CBlock" or datos_user["Status"]=="CWarning1" or datos_user["Status"]=="CWarning2":
    #    datos_user["Status"]="Company"
    #    guardar_datos_status(datos_user)

    usuario=Usuario(datos_user["Usuario"], datos_user["Password"], datos_user["Salt"], path, datos_user["Cuentas"], datos_user["Status"])
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

    tipo_cuenta="User"
    print("\n")
    print("\033[93m--------------------------------")
    print("(1) Particular")
    print("(2) Empresa")
    print("\033[93m--------------------------------")
    sel=input("\n\033[94mElija su tipo de cuenta: ")
    if sel=="2":
        tipo_cuenta="Verification"
        empresas_formulario(user)

    elif sel!=1 and sel!=2:
        print("\033[91mError: Esa opción es incorrecta\n")
        home()

    #Si el usuario no existe, se procede a su registro

    password=input("\n\033[94mIntroduzca su contraseña (Recuerde que debe contener mayúsculas, minúsculas y números, con al menos 6 caracteres): ")

    #Se comprueba que la contraseña cumpla con las condiciones
    if not re.match(password_pattern, password):
        print("\033[91mError: Recuerde que la contraseña debe contener mayúsculas,\nminúsculas y números, con al menos 6 caracteres\n")
        registrarse()

    key=derive(password)

    user_data_dict={"Usuario": user, "Password": key[0], "Salt": key[1], "Cuentas": [], "Status":tipo_cuenta}


    #Se registra al usuario
    with open(path, "w") as file:
        json.dump(user_data_dict, file)

    #Generamos la CSR
    if tipo_cuenta=="Verification":
        company = Empresa(user)
        csr_company(company, user, password)

    print("\033[92m¡Usuario registrado con éxito! \n")

    home()


def empresas_formulario(user):
    empresa_nombre=input("\n\033[94mIntroduzca el nombre de su compañía: ")
    empresa_pais=input("\n\033[94mIntroduzca el país desde el que opera su compañía(ej: 'ES'): ")
    while not len(empresa_pais)==2:
        empresa_pais = input("\n\033[91mError: país debe ser un código de dos letras (ej: 'ES'): ")
    empresa_estado = input("\n\033[94mIntroduzca el estado o provincia desde el que opera su compañía: ")
    empresa_ciudad = input("\n\033[94mIntroduzca la ciudad desde la que opera su compañía: ")
    empresa_web=input("\n\033[94mIntroduzca el dominio web de su compañía (www.company.com): ")
    #Se comprueba que el dominio sea válido
    if not re.match(domain_pattern, empresa_web):
        print("\033[91mError: El dominio introducido no es válido\n")
        registrarse()

    new_company={"Usuario":user,
                 "Nombre":empresa_nombre,
                 "Pais":empresa_pais,
                 "Estado":empresa_estado,
                 "Ciudad":empresa_ciudad,
                 "Web":empresa_web}
    #Se registra a la empresa
    with open("Database/Company_Data/"+user+".json", "w") as file:
        json.dump(new_company, file)




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

    pin_claro=str(input("\033[94mIntroduzca un pin (4 números) para proteger su cuenta: "))

    #Se comprueba que el pin cumpla con las condiciones
    if not re.match(pin_pattern, pin_claro):
        print("\033[91mError: Recuerde el pin debe contener exactamente 4 números")
        crear_cuenta(usuario)

    pin=pbkdf2_derive(pin_claro)

    #encriptamos el saldo
    f=fernet_encrypt(str(0), pin_claro.encode("latin-1"), pin[1])


    cuenta_nueva={"Propietario": usuario.nombre, "Numero de cuenta": numero_cuenta, "Pin": pin[0], "Salt": pin[1], "Saldo":f[0], "Path":path_cuentas, "Transferencias":[], "Solicitudes":[], "Facturas":[]}



    with open(path_cuentas, "w") as file:
        json.dump(cuenta_nueva, file)


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



    cuenta_usuario=Cuenta(datos_cuenta["Propietario"], datos_cuenta["Numero de cuenta"], datos_cuenta["Pin"], datos_cuenta["Salt"], float(0), datos_cuenta["Path"], datos_cuenta["Transferencias"], "pin", datos_cuenta["Solicitudes"], datos_cuenta["Facturas"])

    pin = input("\n\033[94mIntroduzca el pin de su cuenta bancaria (Escriba '0' para volver): ")
    if pin == "0":
        cuentas(usuario)

    try:
        pbkdf2_verify(pin, cuenta_usuario.pin.encode('latin-1'), cuenta_usuario.salt.encode('latin-1'))
    except:
        print("\033[91mError: Su pin no es correcto\n")
        cuentas(usuario)

    #Si el pin es correcto, lo utilizamos para derivar y obtener el saldo
    saldo_user = fernet_decrypt(datos_cuenta["Saldo"], pin.encode("latin-1"), cuenta_usuario.salt)
    cuenta_usuario.saldo=float(saldo_user)
    cuenta_usuario.pinclaro=pin


    operaciones(usuario, cuenta_usuario)

def transferencias_recibidas(cuenta):
    """Función para generar una notificación cuando se recibe una transferencia"""

    for i in cuenta.transferencias:
        indice=cuenta.transferencias.index(i)
        cuenta.transferencias.pop(indice)
        data=obtener_datos("Database/Transferencias/"+i+".json")
        cuenta.saldo+=float(data["Cantidad"])
        saldo = fernet_encrypt(str(cuenta.saldo), cuenta.pinclaro.encode("latin-1"), cuenta.salt)[0]
        print("\033[91m⚠ \033[92m¡Ha recibido una transferencia de", data["Remitente"], "("+str(data["Cantidad"])+"€)!")

        user_data_dict = {"Propietario": cuenta.propietario, "Numero de cuenta": cuenta.cuenta, "Pin": cuenta.pin, "Salt": cuenta.salt,
                          "Saldo": saldo, "Path": cuenta.path, "Transferencias": cuenta.transferencias, "Solicitudes": cuenta.solicitudes, "Facturas":cuenta.facturas}
        with open(cuenta.path, "w") as file:
            json.dump(user_data_dict, file)
    return cuenta

def solicitudes_recibidas(cuenta, usuario):
    """Función para generar una notificación cuando se recibe una transferencia"""
    recibido=False
    password="0"
    if len(cuenta.solicitudes)>0:
        password=input("\033[94mIntroduzca su contraseña para ver las solicitudes pendientes (Escriba '0' para descartar): ")
    if password!="0":
        try:
            verify(password, usuario.password.encode("latin-1"), usuario.salt.encode('latin-1'))
        except:
            print("\033[91mError: Su contraseña no es correcta\n")
            solicitudes_recibidas(cuenta, usuario)
        for i in cuenta.solicitudes:
            indice=cuenta.solicitudes.index(i)
            cuenta.solicitudes.pop(indice)
            data=obtener_datos("Database/Solicitudes/"+i+".json")
            firma=obtener_datos("Database/Solicitudes/Sign/"+i+".json")
            saldo = fernet_encrypt(str(cuenta.saldo), cuenta.pinclaro.encode("latin-1"), cuenta.salt)[0]

            remitente_dc = rsa_decrypt(data["Remitente"], usuario.nombre, password)
            cuenta_dc = rsa_decrypt(data["Cuenta"], usuario.nombre, password)
            cantidad_dc = rsa_decrypt(data["Cantidad"], usuario.nombre, password)

            try:
                rsa_verify_sign(remitente_dc, firma, i)
                print("\033[91m⚠ \033[92m", remitente_dc,
                        "le ha solicitado un ingreso de " + cantidad_dc + "€ a la cuenta "+cuenta_dc+".\nConcepto: \033[92m\033[96m", data["Concepto"])
                recibido=True
                user_data_dict = {"Propietario": cuenta.propietario, "Numero de cuenta": cuenta.cuenta, "Pin": cuenta.pin,
                                  "Salt": cuenta.salt,
                                  "Saldo": saldo, "Path": cuenta.path, "Transferencias": cuenta.transferencias,
                                  "Solicitudes": cuenta.solicitudes, "Facturas": cuenta.facturas}
                with open(cuenta.path, "w") as file:
                    json.dump(user_data_dict, file)
            except:
                pass
    if recibido:
        print("\033[94mPuede realizar el ingreso en '(4) Realizar una transferencia'\n")
    return cuenta

def facturas_recibidas(cuenta, usuario):
    """Función para generar una notificación cuando se recibe una transferencia"""
    password="0"
    if len(cuenta.facturas)>0:
        password=input("\033[94mIntroduzca su contraseña para ver las facturas pendientes (Escriba '0' para descartar): ")
    if password!="0":
        try:
            verify(password, usuario.password.encode("latin-1"), usuario.salt.encode('latin-1'))
        except:
            print("\033[91mError: Su contraseña no es correcta\n")
            facturas_recibidas(cuenta, usuario)
        for i in cuenta.facturas:
            indice=cuenta.facturas.index(i)
            cuenta.facturas.pop(indice)
            data=obtener_datos("Database/Facturas/"+i+".json")
            firma=obtener_datos("Database/Facturas/Sign/"+i+".json")

            remitente_dc = rsa_decrypt(data["Remitente"], usuario.nombre, password)
            cuenta_dc = rsa_decrypt(data["Cuenta"], usuario.nombre, password)
            cantidad_dc = rsa_decrypt(data["Cantidad"], usuario.nombre, password)

            try:
                cert_verify_company(remitente_dc)
                rsa_verify_sign(remitente_dc, firma, i)
                print("\033[91m⚠ \033[92m", remitente_dc,
                        "le ha cobrado " + cantidad_dc + "€ a la cuenta "+cuenta_dc+".\nConcepto: \033[92m\033[96m", data["Concepto"])
                recibido=True
                cuenta.saldo -= float(cantidad_dc)
                saldo = fernet_encrypt(str(cuenta.saldo), cuenta.pinclaro.encode("latin-1"), cuenta.salt)[0]
                user_data_dict = {"Propietario": cuenta.propietario, "Numero de cuenta": cuenta.cuenta, "Pin": cuenta.pin,
                                  "Salt": cuenta.salt,
                                  "Saldo": saldo, "Path": cuenta.path, "Transferencias": cuenta.transferencias,
                                  "Solicitudes": cuenta.solicitudes, "Facturas": cuenta.facturas}
                with open(cuenta.path, "w") as file:
                    json.dump(user_data_dict, file)
            except:
                pass
    return cuenta




######################################################################################################################
######################################################################################################################
# GESTIÓN DE OPERACIONES
######################################################################################################################
######################################################################################################################


def operaciones(usuario, cuenta):
    print("\n")
    cuenta=transferencias_recibidas(cuenta)
    cuenta=solicitudes_recibidas(cuenta, usuario)
    cuenta=facturas_recibidas(cuenta, usuario)
    print("\033[93m--------------------------------")
    print("(1) Consultar saldo")
    print("(2) Retirar dinero")
    print("(3) Ingresar dinero")
    print("(4) Realizar una transferencia")
    print("(5) Solicitar una transferencia")
    print("(6) Cambiar de cuenta")
    print("(7) Borrar cuenta")
    print("(8) Cerrar sesión")
    if usuario.status=="Company":
        print("\033[35m(9) Emitir factura ")
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
        dinero_solicitar(usuario, cuenta)
    elif sel=="6":
        del(cuenta)
        cuentas(usuario)
    elif sel=="7":
        borrar_cuenta(usuario, cuenta)
    elif sel=="8":
        del(cuenta)
        del(usuario)
        print("\033[92mSe ha cerrado la sesión, hasta pronto...\n")
        home()
    elif usuario.status=="Company" and sel=="9":
        dinero_empresa_factura(usuario, cuenta)
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


    cuenta_destino=Cuenta(datos_cuenta["Propietario"], datos_cuenta["Numero de cuenta"], datos_cuenta["Pin"], datos_cuenta["Salt"], datos_cuenta["Saldo"], datos_cuenta["Path"], datos_cuenta["Transferencias"], "pin", datos_cuenta["Solicitudes"], datos_cuenta["Facturas"])


    #Guardamos el recibo de la transferencia

    numero_transferencia=exrex.getone(r'TR[a-zA-Z0-9]{6}'+str(int(datetime.datetime.utcnow().timestamp())))
    transferencia_datos={"Remitente": cuenta.propietario, "Destinatario": cuenta_destino.propietario, "Cantidad":ret, "Fecha":str(datetime.datetime.utcnow()), "Path":"Database/Transferencias/"+numero_transferencia+".json"}
    cuenta_destino.transferencias.append(numero_transferencia)

    with open(transferencia_datos["Path"],"w+") as file:
        json.dump(transferencia_datos, file)

    print("\033[92m¡Transferencia realizada con éxito!")

    guardar_datos_cuenta_transferencia(usuario, cuenta, cuenta_destino)

def dinero_solicitar(usuario, cuenta):
    pin = input("\n\033[94mIntroduzca el pin de su cuenta bancaria (Escriba '0' para volver): ")
    if pin == "0":
        operaciones(usuario, cuenta)

    try:
        pbkdf2_verify(pin, cuenta.pin.encode('latin-1'), cuenta.salt.encode('latin-1'))
    except:
        print("\033[91mError: Su pin no es correcto\n")
        cuentas(usuario)

    cuenta_ingreso = input("\n\033[94m¿A qué cuenta desea solicitar el dinero (Recuerde respetar las mayúsculas)?: ")
    if not os.path.exists("Database/Cuentas/"+cuenta_ingreso+".json"):
        print("\033[91mError: Esa cuenta no existe\n")
        operaciones(usuario, cuenta)

    if cuenta_ingreso==cuenta.cuenta or (cuenta in usuario.cuentas):
        print("\033[91mError: No puede hacer una solicitud de pago a usted mismo\n")
        operaciones(usuario, cuenta)

    cant = input("\n\033[94m¿Cuánto dinero quiere solicitar?: ")
    try:
        cant=float(cant)
    except:
        print("\033[91mError: Debe introducir un número, los decimales se indican con '.'\n")
        operaciones(usuario, cuenta)

    if cant<=0:
        print("\033[91mError: No puede transferir dinero negativo")
        dinero_saldo(usuario, cuenta)

    concepto=input("\n\033[94m¿Cuál es el concepto de la solicitud? (Mínimo 4 caracteres): ")
    while len(concepto)<4:
        print("\033[91mError: Debe especificar un concepto para la operación (Mínimo 4 caracteres) o escribir '0' para cancelar")
        concepto = input("\n\033[94m¿Cuál es el concepto de la solicitud?: ")
        if concepto=="0":
            operaciones(usuario, cuenta)

    password=input("\n\033[94mIntroduzca su contraseña para confirmar la solicitud: ")

    try:
        verify(password, usuario.password.encode('latin-1'), usuario.salt.encode('latin-1'))
    except:
        print("\033[91mError: Su contraseña no es correcta\n")
        seleccionar_cuenta(usuario)

    #Obtenemos los datos de la cuenta a la que se realiza la solicitud

    datos_cuenta = obtener_datos("Database/Cuentas/" + cuenta_ingreso + ".json")
    cuenta_destino = Cuenta(datos_cuenta["Propietario"], datos_cuenta["Numero de cuenta"], datos_cuenta["Pin"],
                            datos_cuenta["Salt"], datos_cuenta["Saldo"], datos_cuenta["Path"],
                            datos_cuenta["Transferencias"], "pin", datos_cuenta["Solicitudes"], datos_cuenta["Facturas"])

    #Guardamos el recibo de la solicitud

    numero_transferencia=exrex.getone(r'SL[a-zA-Z0-9]{4}'+str(int(datetime.datetime.utcnow().timestamp()))[7:])
    #Firmamos el número de transferencia para evitar la suplantación de identidad

    solicitud_datos={"Remitente": cuenta.propietario, "Destinatario": cuenta_destino.propietario, "Cuenta": cuenta.cuenta, "Cantidad":str(cant), "Concepto":concepto, "Fecha":str(datetime.datetime.utcnow()), "Path":"Database/Solicitudes/"+numero_transferencia+".json"}

    #Convertimos el diccionario con los datos de la solicitud a str, lo convertimos a bytes y firmamos su contenido
    #para que no pueda ser modificado ningún dato.

    #Encriptamos los datos sensibles
    remitente_encrypt=rsa_encrypt(cuenta.propietario,cuenta_destino.propietario)
    cuenta_encrypt = rsa_encrypt(cuenta.cuenta, cuenta_destino.propietario)
    cantidad_encrypt = rsa_encrypt(str(cant), cuenta_destino.propietario)
    solicitud_datos["Remitente"]=remitente_encrypt
    solicitud_datos["Cuenta"]=cuenta_encrypt
    solicitud_datos["Cantidad"]=cantidad_encrypt

    #Firmamos y encriptamos
    data_sign = rsa_sign_text(usuario.nombre, password, numero_transferencia)
   # data_sing_encrypt = rsa_encrypt(data_sign,cuenta_destino.propietario)

    cuenta_destino.solicitudes.append(numero_transferencia)

    with open(solicitud_datos["Path"],"w+") as file:
        json.dump(solicitud_datos, file)

    with open("Database/Solicitudes/Sign/"+numero_transferencia+".json","w+") as file:
        json.dump(data_sign, file)

    print("\033[92m¡Solicitud realizada con éxito!")

    guardar_datos_cuenta_transferencia(usuario, cuenta, cuenta_destino)


def dinero_empresa_factura(usuario, cuenta):
    pin = input("\n\033[94mIntroduzca el pin de su cuenta bancaria (Escriba '0' para volver): ")
    if pin == "0":
        operaciones(usuario, cuenta)

    try:
        pbkdf2_verify(pin, cuenta.pin.encode('latin-1'), cuenta.salt.encode('latin-1'))
    except:
        print("\033[91mError: Su pin no es correcto\n")
        cuentas(usuario)

    cuenta_ingreso = input("\n\033[94m¿A qué cuenta desea emitir la factura (Recuerde respetar las mayúsculas)?: ")
    if not os.path.exists("Database/Cuentas/"+cuenta_ingreso+".json"):
        print("\033[91mError: Esa cuenta no existe\n")
        operaciones(usuario, cuenta)

    if cuenta_ingreso==cuenta.cuenta or (cuenta in usuario.cuentas):
        print("\033[91mError: No puede hacer una factura a usted mismo\n")
        operaciones(usuario, cuenta)

    cant = input("\n\033[94m¿Cuánto dinero debe cobrar?: ")
    try:
        cant=float(cant)
    except:
        print("\033[91mError: Debe introducir un número, los decimales se indican con '.'\n")
        operaciones(usuario, cuenta)

    if cant<=0:
        print("\033[91mError: No puede cobrar dinero negativo")
        dinero_saldo(usuario, cuenta)

    concepto=input("\n\033[94m¿Cuál es el concepto de la factura? (Mínimo 4 caracteres): ")
    while len(concepto)<4:
        print("\033[91mError: Debe especificar un concepto para la operación (Mínimo 4 caracteres) o escribir '0' para cancelar")
        concepto = input("\n\033[94m¿Cuál es el concepto de la factura?: ")
        if concepto=="0":
            operaciones(usuario, cuenta)

    password=input("\n\033[94mIntroduzca su contraseña para confirmar la factura: ")

    try:
        verify(password, usuario.password.encode('latin-1'), usuario.salt.encode('latin-1'))
    except:
        print("\033[91mError: Su contraseña no es correcta\n")
        seleccionar_cuenta(usuario)

    #Obtenemos los datos de la cuenta a la que se realiza la solicitud

    datos_cuenta = obtener_datos("Database/Cuentas/" + cuenta_ingreso + ".json")
    cuenta_destino = Cuenta(datos_cuenta["Propietario"], datos_cuenta["Numero de cuenta"], datos_cuenta["Pin"],
                            datos_cuenta["Salt"], datos_cuenta["Saldo"], datos_cuenta["Path"],
                            datos_cuenta["Transferencias"], "pin", datos_cuenta["Solicitudes"], datos_cuenta["Facturas"])

    #Guardamos el recibo de la solicitud

    numero_transferencia=exrex.getone(r'FC[a-zA-Z0-9]{4}'+str(int(datetime.datetime.utcnow().timestamp()))[7:])
    #Firmamos el número de transferencia para evitar la suplantación de identidad

    solicitud_datos={"Remitente": cuenta.propietario, "Destinatario": cuenta_destino.propietario, "Cuenta": cuenta.cuenta, "Cantidad":str(cant), "Concepto":concepto, "Fecha":str(datetime.datetime.utcnow()), "Path":"Database/Facturas/"+numero_transferencia+".json"}

    #Convertimos el diccionario con los datos de la solicitud a str, lo convertimos a bytes y firmamos su contenido
    #para que no pueda ser modificado ningún dato.

    #Encriptamos los datos sensibles
    remitente_encrypt=rsa_encrypt(cuenta.propietario,cuenta_destino.propietario)
    cuenta_encrypt = rsa_encrypt(cuenta.cuenta, cuenta_destino.propietario)
    cantidad_encrypt = rsa_encrypt(str(cant), cuenta_destino.propietario)
    solicitud_datos["Remitente"]=remitente_encrypt
    solicitud_datos["Cuenta"]=cuenta_encrypt
    solicitud_datos["Cantidad"]=cantidad_encrypt

    #Firmamos y encriptamos
    data_sign = rsa_sign_text(usuario.nombre, password, numero_transferencia)
   # data_sing_encrypt = rsa_encrypt(data_sign,cuenta_destino.propietario)
    cuenta.saldo+=float(cant)
    cuenta_destino.facturas.append(numero_transferencia)

    with open(solicitud_datos["Path"],"w+") as file:
        json.dump(solicitud_datos, file)

    with open("Database/Facturas/Sign/"+numero_transferencia+".json","w+") as file:
        json.dump(data_sign, file)

    print("\033[92m¡Factura enviada con éxito!")

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
    user_data_dict={"Usuario": usuario.nombre, "Password": usuario.password, "Salt": usuario.salt, "Path": usuario.path, "Cuentas": usuario.cuentas, "Status": usuario.status}
    with open(usuario.path, "w") as file:
        json.dump(user_data_dict, file)

def guardar_datos_status(usuario_data):
    with open(usuario_data["Path"], "w") as file:
        json.dump(usuario_data, file)

def guardar_datos_cuenta(usuario, cuenta):
    saldo=fernet_encrypt(str(cuenta.saldo), cuenta.pinclaro.encode("latin-1"), cuenta.salt)
    #Buscamos el diccionario de symetric keys
    ##lista_keys=obtener_datos("Database/System/symetric_keys.json")
    #Añadimos la nueva key (EN SITUACIÓN REAL, NUNCA SE DEBE ALMACENAR EN CLARO)
    ##lista_keys[cuenta.cuenta]=saldo[1]
    #Guardamos el diccionario de keys
    #with open("Database/System/symetric_keys.json", "w+") as file:
    #    json.dump(lista_keys, file)

    user_data_dict={"Propietario": cuenta.propietario, "Numero de cuenta": cuenta.cuenta, "Pin": cuenta.pin, "Salt":cuenta.salt, "Saldo":saldo[0], "Path":cuenta.path, "Transferencias":cuenta.transferencias, "Solicitudes": cuenta.solicitudes, "Facturas":cuenta.facturas}
    with open(cuenta.path, "w") as file:
        json.dump(user_data_dict, file)
    operaciones(usuario, cuenta)

def guardar_datos_cuenta_transferencia(usuario, cuenta, cuentadest):

    #Ciframos saldo usuario que transfiere
    saldo_tr=fernet_encrypt(str(cuenta.saldo), cuenta.pinclaro.encode("latin-1"), cuenta.salt)


    user_data_dict={"Propietario": cuenta.propietario, "Numero de cuenta": cuenta.cuenta, "Pin": cuenta.pin, "Salt":cuenta.salt, "Saldo":saldo_tr[0], "Path":cuenta.path, "Transferencias":cuenta.transferencias, "Solicitudes": cuenta.solicitudes, "Facturas":cuenta.facturas}
    dest_data_dict={"Propietario": cuentadest.propietario, "Numero de cuenta": cuentadest.cuenta, "Pin": cuentadest.pin, "Salt":cuentadest.salt, "Saldo":cuentadest.saldo, "Path":cuentadest.path, "Transferencias":cuentadest.transferencias, "Solicitudes": cuentadest.solicitudes, "Facturas":cuentadest.facturas}



    with open(cuenta.path, "w") as file:
        json.dump(user_data_dict, file)
    with open(cuentadest.path, "w") as file:
        json.dump(dest_data_dict, file)
    operaciones(usuario, cuenta)

home()
