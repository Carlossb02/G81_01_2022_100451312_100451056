
class Cuenta():
    def __init__(self, propietario, cuenta, pin, salt, saldo, path, transferencias):
        self.propietario=propietario
        self.cuenta=cuenta
        self.pin=pin
        self.salt=salt
        self.saldo=saldo
        self.path=path
        self.transferencias=transferencias
