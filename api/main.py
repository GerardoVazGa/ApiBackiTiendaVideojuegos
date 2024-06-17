from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, Query, status
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from models import CarritoItem, ProductoUpdate, Tienda, Token, TokenData, Usuario, ProductoVideojuego, Venta, Empleado
from fastapi.middleware.cors import CORSMiddleware
from uuid import uuid4
import jwt # type: ignore

app = FastAPI()

origins = [
    "http://localhost:4200",  # Cambia esto a la URL de tu aplicación Angular
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conexión al clúster de Cassandra
cluster = Cluster(['172.16.158.116', '172.16.156.170', '172.16.154.210', '172.16.152.246'])
session = cluster.connect('tiendavideojuegos')

# Configuración de JWT
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

carritos = {}

@app.get("/")
def read_root():
    return {"message": "API de Tienda de Videojuegos está en funcionamiento"}

@app.post("/tiendas/")
def create_tienda(tienda: Tienda):
    query = "INSERT INTO tienda (nombre, direccion, correo, telefono) VALUES (%s, %s, %s, %s)"
    session.execute(query, (tienda.nombre, tienda.direccion, tienda.correo, tienda.telefono))
    return tienda

@app.get("/tiendas/{nombre}")
def read_tienda(nombre: str):
    query = "SELECT nombre, direccion, correo, telefono FROM tienda WHERE nombre=%s"
    tienda = session.execute(query, (nombre,)).one()
    if tienda:
        return {"nombre": tienda.nombre, "direccion": tienda.direccion, "correo": tienda.correo, "telefono": tienda.telefono}
    else:
        raise HTTPException(status_code=404, detail="Tienda not found")

#Crear token de acceso de usuario    
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#obtener usuario actual mediante el rol
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("rol")
        if username is None or role is None:
            raise credentials_exception
        token_data = TokenData(username=username, role=role)
    except jwt.PyJWTError:
        raise credentials_exception
    user = get_user_by_name(token_data.username)
    if user is None:
        raise credentials_exception
    return user

#condicion de que rol para verificar si es administrador el usuario
def admin_required(current_user: Usuario = Depends(get_current_user)):
    if current_user["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted",
        )

#obtener el usuario en caso de que se encuentre ya registrado
def get_user_by_name(username: str):
    query = "SELECT nombre, password, rol, nombre_tienda FROM usuario WHERE nombre=%s "
    usuario = session.execute(query, (username,)).one()
    if usuario:
        return {
            "nombre": usuario.nombre,
            "password": usuario.password,
            "rol": usuario.rol,
            "nombre_tienda": usuario.nombre_tienda
        }
    return None

#Generador de token para autenticar
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_name(form_data.username)
    if not user or form_data.password != user["password"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # Correct usage of timedelta
    access_token = create_access_token(
        data={"sub": user["nombre"], "rol": user["rol"]}, expires_delta=access_token_expires
    )

    print(f'Usuario: {user["nombre"]}, Rol: {user["rol"]}') 
    return {"access_token": access_token, "token_type": "bearer", "rol": user["rol"]}


@app.get("/usuarios/me", response_model=Usuario)
async def read_users_me(current_user: Usuario = Depends(get_current_user)):
    return current_user

#Consulta para saber si el usuario existe
def username_exists(username: str):
    query = "SELECT COUNT(*) FROM usuario WHERE nombre=%s"
    result = session.execute(query, (username,))
    return result.one()[0] > 0

#identificar que el usuario esta en existencia en la bd
@app.post("/usuarios/")
def create_usuario(usuario: Usuario):
    if username_exists(usuario.nombre):
        raise HTTPException(status_code=400, detail="El nombre de usuario ya está en uso")
    
    # Insertar el usuario en la base de datos si no existe
    query = "INSERT INTO usuario (nombre, password, rol, nombre_tienda) VALUES (%s, %s, %s, %s)"
    session.execute(query, (usuario.nombre, usuario.password, usuario.rol, usuario.nombre_tienda))
    return usuario

# Función para obtener la dirección de la tienda a partir del nombre de la tienda
def get_store_info(store_name: str):
    query = "SELECT direccion FROM tienda WHERE nombre=%s"
    tienda = session.execute(query, (store_name,)).one()
    if tienda:
        return tienda.direccion
    return None

# Función para crear un producto
def create_product(producto: ProductoVideojuego, current_user: Usuario):
    # Obtener la dirección de la tienda del administrador actual
    direccion_tienda = get_store_info(current_user["nombre_tienda"])
    if not direccion_tienda:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró la dirección de la tienda {current_user['nombre_tienda']}",
        )
    
    # Asignar la dirección y nombre de la tienda al producto
    producto.nombre_tienda = current_user["nombre_tienda"]
    producto.direccion_tienda = direccion_tienda
    
    # Insertar el producto en la base de datos
    query = "INSERT INTO productoVideojuego (titulo, plataforma, categoria, precio, cantidad, nombre_tienda, direccion_tienda) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    session.execute(query, (producto.titulo, producto.plataforma, producto.categoria, producto.precio, producto.cantidad, producto.nombre_tienda, producto.direccion_tienda))

# Ruta para registrar un nuevo producto
@app.post("/productos/")
def create_producto(producto: ProductoVideojuego, current_user: Usuario = Depends(get_current_user)):
    # Verificar si el usuario es administrador
    if current_user["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operación no permitida",
        )
    
    # Crear el producto en la base de datos
    create_product(producto, current_user)
    
    return producto

#Agregar videojuego siendo de la tienda a la que pertenece el administrador
@app.put("/productos/{titulo}")
def update_producto(titulo: str, producto: ProductoUpdate, current_user: Usuario = Depends(get_current_user)):
    if current_user["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operación no permitida: Solo los administradores pueden actualizar productos",
        )
    
    print(f'Debug: current_user = {current_user}')
    
    if "nombre_tienda" not in current_user:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falta el campo 'nombre_tienda' en el usuario actual",
        )

    if not check_producto_belongs_to_tienda(titulo, current_user["nombre_tienda"]):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Producto con título {titulo} no encontrado en la tienda del administrador",
        )
    
    query = "UPDATE productoVideojuego SET precio=%s, cantidad=%s WHERE titulo=%s"
    session.execute(query, (producto.precio, producto.cantidad, titulo))
    
    return {"message": f"Precio y cantidad del producto {titulo} actualizados correctamente"}

#Consulta de que el videojuego ya este registrado en la tienda
def check_producto_belongs_to_tienda(titulo: str, nombre_tienda: str):
    query = "SELECT COUNT(*) FROM productoVideojuego WHERE titulo=%s AND nombre_tienda=%s  ALLOW FILTERING"
    result = session.execute(query, (titulo, nombre_tienda))
    return result.one()[0] > 0

#Eliminar productos si es administrador
@app.delete("/productos/{titulo}")
def delete_producto(titulo: str, current_user: Usuario = Depends(get_current_user)):
    # Verificar si el usuario es administrador
    if current_user["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operación no permitida: Solo los administradores pueden eliminar productos",
        )
    
    # Verificar si el producto existe y pertenece a la tienda del administrador
    if not check_producto_belongs_to_tienda(titulo, current_user["nombre_tienda"]):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Producto con título {titulo} no encontrado en la tienda del administrador",
        )
    
    # Eliminar el producto de la base de datos
    query = "DELETE FROM productoVideojuego WHERE titulo=%s"
    session.execute(query, (titulo,))
    
    return {"message": f"Producto {titulo} eliminado correctamente"}


#peticion de los productos para poder mostrarse
@app.get("/productos/")
def read_productos(current_user: Usuario = Depends(get_current_user)):
    # Verificar si el usuario es administrador
    if current_user["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted",
        )
    # Obtener las ventas de la tienda del administrador
    nombre_tienda = current_user["nombre_tienda"]
    query = "SELECT titulo, plataforma, categoria, precio, cantidad, nombre_tienda, direccion_tienda FROM productoVideojuego WHERE nombre_tienda=%s ALLOW FILTERING"
    productos = session.execute(query, (nombre_tienda,)).all()
    
    return [
        {
            "titulo": producto.titulo,
            "plataforma": producto.plataforma,
            "categoria": producto.categoria,
            "precio": producto.precio,
            "cantidad": producto.cantidad,
            "nombre_tienda": producto.nombre_tienda,
            "direccion_tienda": producto.direccion_tienda
        } for producto in productos
    ]

@app.get("/productos/tienda/{nombre_tienda}")
def read_productos_by_tienda(nombre_tienda: str):
    query = "SELECT titulo, plataforma, categoria, precio, cantidad, nombre_tienda, direccion_tienda FROM productoVideojuego WHERE nombre_tienda=%s ALLOW FILTERING"
    productos = session.execute(query, (nombre_tienda,)).all()
    
    return [
        {
            "titulo": producto.titulo,
            "plataforma": producto.plataforma,
            "categoria": producto.categoria,
            "precio": producto.precio,
            "cantidad": producto.cantidad,
            "nombre_tienda": producto.nombre_tienda,
            "direccion_tienda": producto.direccion_tienda
        } for producto in productos
    ]

@app.post("/ventas/")
def create_venta(venta: Venta):
    query = "INSERT INTO venta (titulo_producto, cantidad, nombre_tienda, categoria_producto, plataforma, precio_producto, total_pagar) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    session.execute(query, (venta.titulo_producto, venta.cantidad, venta.nombre_tienda, venta.categoria_producto, venta.plataforma, venta.precio_producto, venta.total_pagar))
    return venta

#mostrar ventas dependiendo de la tienda a la que se encuentra el admininstrador

@app.get("/ventas/mi-tienda")
async def read_ventas_mi_tienda(current_user: Usuario = Depends(get_current_user)):
    # Verificar si el usuario es administrador
    if current_user["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted",
        )
    # Obtener las ventas de la tienda del administrador
    nombre_tienda = current_user["nombre_tienda"]
    query = "SELECT titulo_producto, cantidad, plataforma, precio_producto, total_pagar FROM venta WHERE nombre_tienda=%s ALLOW FILTERING"
    ventas = session.execute(query, (nombre_tienda,)).all()
    
    return [
        {
            "titulo_producto": venta.titulo_producto,
            "cantidad": venta.cantidad,
            "plataforma": venta.plataforma,
            "precio_producto": venta.precio_producto,
            "total_pagar": venta.total_pagar
        } for venta in ventas
    ]

@app.post("/empleados/")
def create_empleado(empleado: Empleado):
    query = "INSERT INTO empleado (nombre, apellido, cargo, nombre_tienda, direccion_tienda) VALUES (%s, %s, %s, %s, %s)"
    session.execute(query, (empleado.nombre, empleado.apellido, empleado.cargo, empleado.nombre_tienda, empleado.direccion_tienda))
    return empleado

#Obtiene los emplesdos segun la tienda a la que pertenece el administrador
@app.get("/empleados/mi-tienda")
async def read_empleados_mi_tienda(current_user: Usuario = Depends(get_current_user)):
    # Verificar si el usuario es administrador
    if current_user["rol"] != "administrador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted",
        )
    # Obtener los empleados de la tienda del administrador
    nombre_tienda = current_user["nombre_tienda"]
    query = "SELECT nombre, apellido, cargo, direccion_tienda FROM empleado WHERE nombre_tienda=%s ALLOW FILTERING"
    empleados = session.execute(query, (nombre_tienda,)).all()
    
    response_data = {
        "nombre_tienda": nombre_tienda,
        "empleados": [
            {
                "nombre": empleado.nombre,
                "apellido": empleado.apellido,
                "cargo": empleado.cargo
            } for empleado in empleados
        ]
    }
    
    return response_data

# Función para agregar un producto al carrito
def add_to_cart(item: CarritoItem, user_id: str):
    if user_id not in carritos:
        carritos[user_id] = []
    
    # Consultar el precio del producto desde la base de datos (Cassandra)
    query = "SELECT precio FROM productoVideojuego WHERE titulo=%s"
    result = session.execute(query, (item.nombre,))
    producto = result.one()
    
    if producto:
        precio_unitario = producto.precio
        precio_total = item.cantidad * precio_unitario
        
        carrito_item = {
            "nombre": item.nombre,
            "cantidad": item.cantidad,
            "precio_unitario": precio_unitario,
            "precio_total": precio_total
        }
        
        carritos[user_id].append(carrito_item)
    else:
        raise HTTPException(status_code=404, detail=f"Producto '{item.nombre}' no encontrado")

# Función para eliminar un producto del carrito
def remove_from_cart(item_nombre: str, user_id: str):
    if user_id in carritos:
        carrito_usuario = carritos[user_id]
        for i, item in enumerate(carrito_usuario):
            if item["nombre"] == item_nombre:
                del carrito_usuario[i]
                return {"message": f"Producto '{item_nombre}' eliminado del carrito"}
    
    raise HTTPException(status_code=404, detail=f"Producto '{item_nombre}' no encontrado en el carrito")

# Función para vaciar el carrito
def clear_cart(user_id: str):
    if user_id in carritos:
        del carritos[user_id]

# Función para obtener el contenido del carrito
def get_cart(user_id: str):
    if user_id in carritos:
        return carritos[user_id]
    return []

# Función para registrar la venta en la tabla de ventas
def registrar_venta(user_id: str):
    if user_id not in carritos or not carritos[user_id]:
        raise HTTPException(status_code=400, detail="El carrito está vacío")
    
    cart_items = carritos[user_id]
    total_pagar = sum(item['precio_total'] for item in cart_items)
    
    # Obtener la fecha y hora actual
    fecha_actual = datetime.utcnow()
    
    # Insertar cada producto del carrito como una fila en la tabla venta
    for item in cart_items:
                # Consultar los detalles adicionales del producto desde la tabla productoVideojuego
        query_producto = "SELECT nombre_tienda, categoria, plataforma FROM productoVideojuego WHERE titulo=%s"
        result_producto = session.execute(query_producto, (item['nombre'],))
        producto_info = result_producto.one()
        
        if producto_info:
            nombre_tienda = producto_info.nombre_tienda
            categoria_producto = producto_info.categoria
            plataforma = producto_info.plataforma
        else:
            raise HTTPException(status_code=404, detail=f"No se encontraron detalles para el producto '{item['nombre']}'")
        
        query_venta = """
            INSERT INTO venta (
                titulo_producto, cantidad, nombre_tienda, categoria_producto, plataforma, precio_producto, total_pagar
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        session.execute(query_venta, (
            item['nombre'], item['cantidad'], nombre_tienda, categoria_producto,
            plataforma, item['precio_unitario'], total_pagar
        ))
    
    # Limpiar el carrito después de la compra
    clear_cart(user_id)
    
    return {"message": "Compra realizada correctamente"}

# Ruta para agregar un producto al carrito
@app.post("/carrito/agregar/")
async def agregar_al_carrito(item: CarritoItem, current_user: Usuario = Depends(get_current_user)):
    add_to_cart(item, current_user["nombre"])
    return {"message": "Producto agregado al carrito"}

# Ruta para ver el contenido del carrito
@app.get("/carrito/")
async def ver_carrito(current_user: Usuario = Depends(get_current_user)):
    cart_items = get_cart(current_user["nombre"])
    return {"carrito": cart_items}

# Ruta para realizar la compra (checkout)
@app.post("/compra/")
async def realizar_compra(current_user: Usuario = Depends(get_current_user)):
    return registrar_venta(current_user["nombre"])

# Ruta para vaciar el carrito
@app.delete("/carrito/vaciar/")
async def vaciar_carrito(current_user: Usuario = Depends(get_current_user)):
    clear_cart(current_user["nombre"])
    return {"message": "Carrito vaciado correctamente"}

# Ruta para eliminar un producto del carrito
@app.delete("/carrito/eliminar/{nombre_producto}")
async def eliminar_del_carrito(nombre_producto: str, current_user: Usuario = Depends(get_current_user)):
    return remove_from_cart(nombre_producto, current_user["nombre"])