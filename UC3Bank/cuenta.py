
class Cuenta():
    def __init__(self, propietario, cuenta, pin, salt, saldo, path, transferencias, pinclaro, solicitudes, facturas):
        self.propietario=propietario
        self.cuenta=cuenta
        self.pin=pin
        self.salt=salt
        self.saldo=saldo
        self.path=path
        self.transferencias=transferencias
        self.pinclaro=pinclaro
        self.solicitudes=solicitudes
        self.facturas=facturas