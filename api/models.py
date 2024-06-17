from pydantic import BaseModel
from typing import Optional
from decimal import Decimal

class Tienda(BaseModel):
    nombre: str
    direccion: str
    correo: str
    telefono: str

class Usuario(BaseModel):
    nombre: str
    password: str
    rol: str
    nombre_tienda: str

class ProductoVideojuego(BaseModel):
    titulo: str
    plataforma: str
    categoria: str
    precio: Decimal
    cantidad: int
    nombre_tienda: str
    direccion_tienda: str

class Venta(BaseModel):
    titulo_producto: str
    cantidad: int
    nombre_tienda: str
    categoria_producto: str
    plataforma: str
    precio_producto: Decimal
    total_pagar: Decimal

class Empleado(BaseModel):
    nombre: str
    apellido: str
    cargo: str
    nombre_tienda: str
    direccion_tienda: str

class Token(BaseModel):
    access_token: str
    token_type: str
    rol: str

class TokenData(BaseModel):
    username: str | None = None
    role: str | None = None

class ProductoUpdate(BaseModel):
    precio: float
    cantidad: int

class CarritoItem(BaseModel):
    nombre: str
    cantidad: int
