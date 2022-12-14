import json

class Empresa():
    def __init__(self, usuario):
        self.usuario=usuario
        datos= self.obtener_datos_empresa()
        self.nombre=datos["Nombre"]
        self.pais=datos["Pais"]
        self.estado=datos["Estado"]
        self.ciudad=datos["Ciudad"]
        self.web=datos["Web"]

    def obtener_datos_empresa(self):
        with open("Database/Company_Data/"+self.usuario+".json", "r") as file:
            datos = json.load(file)
        return datos
