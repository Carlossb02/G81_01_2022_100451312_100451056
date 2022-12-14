"""Clase usuario"""


class Usuario:
    def __init__(self, nombre, password, salt, path, cuentas, status):
        self.nombre=nombre
        self.password=password
        self.salt=salt
        self.path=path
        self.cuentas=cuentas
        self.status=status