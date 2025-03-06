import streamlit as st
import mysql.connector
from mysql.connector import Error
import bcrypt
import datetime
import uuid  # Para generar tokens únicos
import pandas as pd  # Para manejar DataFrames y CSV

st.set_page_config(page_title="Customer Sketch", page_icon="icon.ico", layout="wide")

# Configuración de la conexión a MySQL
def create_connection():
    try:
        connection = mysql.connector.connect(
            host="sql213.infinityfree.com",  # Hostname de InfinityFree
            user="if0_38403452",  # Usuario de MySQL
            password="kev1TRQv83896",  # Contraseña de MySQL
            database="if0_38403452_mvp_clientes",  # Nombre de la base de datos
            port=3306  # Puerto de MySQL (opcional)
        )
        return connection
    except Error as e:
        st.error(f"Error al conectar a MySQL: {e}")
        return None

# Función para generar un token de sesión
def generate_session_token():
    return str(uuid.uuid4())

# Función para guardar el token en una cookie
def set_session_cookie(token):
    js = f"""
    <script>
    document.cookie = "session_token={token}; path=/; max-age=86400";  // Cookie válida por 1 día
    </script>
    """
    st.write(js, unsafe_allow_html=True)

# Función para eliminar la cookie al cerrar sesión
def delete_session_cookie():
    js = """
    <script>
    document.cookie = "session_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    </script>
    """
    st.write(js, unsafe_allow_html=True)

# Función para obtener el token de la cookie
def get_session_cookie():
    js = """
    <script>
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }
    const token = getCookie('session_token');
    window.parent.postMessage({type: 'session_token', token: token}, '*');
    </script>
    """
    st.write(js, unsafe_allow_html=True)

# Función para crear un nuevo usuario en la base de datos
def create_user(creado_por, username, password, rol, team_leader_id=None):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        query = """
        INSERT INTO usuarios (username, password_hash, rol, team_leader_id)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (username, hashed_password, rol, team_leader_id))
        connection.commit()
        cursor.close()
        connection.close()
        st.success("Usuario creado exitosamente!")
    else:
        st.error("Error al conectar a la base de datos")

# Función para eliminar un usuario (solo accesible para el Gerente)
def delete_user(user, user_id):
    if user['rol'] != 'gerente':
        st.error("Solo el Gerente puede eliminar usuarios.")
        return

    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        query = "DELETE FROM usuarios WHERE id = %s"
        cursor.execute(query, (user_id,))
        connection.commit()
        cursor.close()
        connection.close()
        st.success("Usuario eliminado exitosamente!")
    else:
        st.error("Error al conectar a la base de datos")

# Interfaz para eliminar un usuario (solo accesible para el Gerente)
def delete_user_ui(user):
    if user['rol'] != 'gerente':
        st.error("Solo el Gerente puede eliminar usuarios.")
        return

    st.subheader("Eliminar Usuario")
    connection = create_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, username FROM usuarios")
        usuarios = cursor.fetchall()
        cursor.close()
        connection.close()

        if usuarios:
            usuario_options = {u['username']: u['id'] for u in usuarios}
            selected_usuario = st.selectbox("Seleccionar Usuario a Eliminar", list(usuario_options.keys()))
            user_id = usuario_options[selected_usuario]

            if st.button("Eliminar Usuario"):
                delete_user(user, user_id)
                st.rerun()
        else:
            st.error("No hay usuarios para eliminar.")

# Interfaz para crear un nuevo usuario (solo accesible para el Gerente)
def create_user_ui(user):
    if user['rol'] != 'gerente':
        st.error("Solo el Gerente puede crear usuarios.")
        return

    st.subheader("Crear Nuevo Usuario")
    username = st.text_input("Nombre de usuario")
    password = st.text_input("Contraseña", type="password")
    rol = st.selectbox("Rol", ["agente_cs", "team_leader", "gerente"])
    team_leader_id = None

    if rol == "agente_cs":
        connection = create_connection()
        if connection:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT id, username FROM usuarios WHERE rol = 'team_leader'")
            team_leaders = cursor.fetchall()
            cursor.close()
            connection.close()

            if team_leaders:
                team_leader_options = {tl['username']: tl['id'] for tl in team_leaders}
                selected_team_leader = st.selectbox("Seleccionar Team Leader", list(team_leader_options.keys()))
                team_leader_id = team_leader_options[selected_team_leader]
            else:
                st.error("No hay Team Leaders disponibles. Primero crea un Team Leader.")
                return

    if st.button("Crear Usuario"):
        if username and password:
            create_user(user['id'], username, password, rol, team_leader_id)
        else:
            st.error("Por favor completa todos los campos.")

# Función para verificar la contraseña hasheada
def check_password(hashed_password, input_password):
    return bcrypt.checkpw(input_password.encode('utf-8'), hashed_password.encode('utf-8'))

# Función para autenticar al usuario
def authenticate_user(username, password):
    connection = create_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        query = "SELECT id, username, password_hash, rol, team_leader_id FROM usuarios WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user and check_password(user['password_hash'], password):
            return user
    return None

# Función para verificar permisos
def check_permissions(user, action, creado_por=None):
    if user['rol'] == 'gerente':
        return True
    elif user['rol'] == 'team_leader':
        if action in ['view', 'edit']:
            return True
    elif user['rol'] == 'agente_cs':
        if action in ['view_self', 'edit_self'] and creado_por == user['id']:
            return True
    return False

# Operación CREATE: Agregar un nuevo cliente
def create_cliente(user, cliente_data):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        query = """
        INSERT INTO clientes (
            creado_por, name, phone, address, email, bank_account, transfer, pin, offer, taxes,
            ssn, tax_id, itin, driving_license, driving_license_expiration, passport, passport_expiration,
            birthdate, billing_card, name_card, zip, cvv, expiration_card, state, city
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            user['id'], cliente_data['name'], cliente_data['phone'], cliente_data['address'],
            cliente_data['email'], cliente_data['bank_account'], cliente_data['transfer'],
            cliente_data['pin'], cliente_data['offer'], cliente_data['taxes'], cliente_data['ssn'],
            cliente_data['tax_id'], cliente_data['itin'], cliente_data['driving_license'],
            cliente_data['driving_license_expiration'], cliente_data['passport'],
            cliente_data['passport_expiration'], cliente_data['birthdate'], cliente_data['billing_card'],
            cliente_data['name_card'], cliente_data['zip'], cliente_data['cvv'],
            cliente_data['expiration_card'], cliente_data['state'], cliente_data['city']
        ))
        connection.commit()
        cursor.close()
        connection.close()
        st.success("Cliente creado exitosamente!")
    else:
        st.error("Error al conectar a la base de datos")

# Operación READ: Obtener clientes según el rol del usuario
def get_clientes(user):
    connection = create_connection()
    if connection:
        cursor = connection.cursor(dictionary=True)
        if user['rol'] == 'gerente':
            query = """
            SELECT c.*, u.username AS creado_por_nombre 
            FROM clientes c
            JOIN usuarios u ON c.creado_por = u.id
            """
            cursor.execute(query)
        elif user['rol'] == 'team_leader':
            query = """
            SELECT c.*, u.username AS creado_por_nombre 
            FROM clientes c
            JOIN usuarios u ON c.creado_por = u.id
            WHERE u.team_leader_id = %s
            """
            cursor.execute(query, (user['id'],))
        elif user['rol'] == 'agente_cs':
            query = """
            SELECT c.*, u.username AS creado_por_nombre 
            FROM clientes c
            JOIN usuarios u ON c.creado_por = u.id
            WHERE c.creado_por = %s
            """
            cursor.execute(query, (user['id'],))
        clientes = cursor.fetchall()
        cursor.close()
        connection.close()
        return clientes
    return []

# Operación UPDATE: Actualizar un cliente existente
def update_cliente(user, cliente_id, cliente_data):
    if not check_permissions(user, 'edit', cliente_data['creado_por']):
        st.error("No tienes permisos para editar este cliente")
        return

    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        query = """
        UPDATE clientes SET
            name = %s, phone = %s, address = %s, email = %s, bank_account = %s, transfer = %s,
            pin = %s, offer = %s, taxes = %s, ssn = %s, tax_id = %s, itin = %s, driving_license = %s,
            driving_license_expiration = %s, passport = %s, passport_expiration = %s, birthdate = %s,
            billing_card = %s, name_card = %s, zip = %s, cvv = %s, expiration_card = %s, state = %s, city = %s
        WHERE id = %s
        """
        cursor.execute(query, (
            cliente_data['name'], cliente_data['phone'], cliente_data['address'],
            cliente_data['email'], cliente_data['bank_account'], cliente_data['transfer'],
            cliente_data['pin'], cliente_data['offer'], cliente_data['taxes'], cliente_data['ssn'],
            cliente_data['tax_id'], cliente_data['itin'], cliente_data['driving_license'],
            cliente_data['driving_license_expiration'], cliente_data['passport'],
            cliente_data['passport_expiration'], cliente_data['birthdate'], cliente_data['billing_card'],
            cliente_data['name_card'], cliente_data['zip'], cliente_data['cvv'],
            cliente_data['expiration_card'], cliente_data['state'], cliente_data['city'], cliente_id
        ))
        connection.commit()
        cursor.close()
        connection.close()
        st.success("Cliente actualizado exitosamente!")
    else:
        st.error("Error al conectar a la base de datos")

# Operación DELETE: Eliminar un cliente
def delete_cliente(user, cliente_id):
    if not check_permissions(user, 'edit'):
        st.error("No tienes permisos para eliminar este cliente")
        return

    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        query = "DELETE FROM clientes WHERE id = %s"
        cursor.execute(query, (cliente_id,))
        connection.commit()
        cursor.close()
        connection.close()
        st.success("Cliente eliminado exitosamente!")
    else:
        st.error("Error al conectar a la base de datos")

# Interfaz para crear un nuevo cliente
def create_cliente_ui(user):
    st.subheader("Crear Nuevo Cliente")
    cliente_data = {
        'name': st.text_input("Name"),
        'phone': st.number_input("Phone", min_value=0),
        'address': st.text_input("Address"),
        'email': st.text_input("Email"),
        'bank_account': st.number_input("Bank Account", min_value=0),
        'transfer': st.text_input("Transfer"),
        'pin': st.number_input("PIN", min_value=0),
        'offer': st.text_input("Offer"),
        'taxes': st.text_input("Taxes"),
        'ssn': st.number_input("SSN", min_value=0),
        'tax_id': st.number_input("Tax ID", min_value=0),
        'itin': st.number_input("ITIN", min_value=0),
        'driving_license': st.text_input("Driving License"),
        'driving_license_expiration': st.date_input("Driving License Expiration", min_value=datetime.date(1900, 1, 1)),
        'passport': st.text_input("Passport"),
        'passport_expiration': st.date_input("Passport Expiration", min_value=datetime.date(1900, 1, 1)),
        'birthdate': st.date_input("Birthdate", min_value=datetime.date(1900, 1, 1)),
        'billing_card': st.number_input("Billing Card", min_value=0),
        'name_card': st.text_input("Name on Card"),
        'zip': st.number_input("ZIP", min_value=0),
        'cvv': st.number_input("CVV", min_value=0),
        'expiration_card': st.date_input("Card Expiration", min_value=datetime.date(1900, 1, 1)),
        'state': st.text_input("State"),
        'city': st.text_input("City")
    }
    if st.button("Crear Cliente"):
        create_cliente(user, cliente_data)

# Interfaz para ver y editar clientes
def view_edit_clientes_ui(user):
    st.subheader("Clientes")
    clientes = get_clientes(user)
    if clientes:
        for cliente in clientes:
            with st.expander(f"Cliente ID: {cliente['id']}"):
                st.write(f"**Creado por:** {cliente['creado_por_nombre']}")  # Mostrar quién creó el registro
                st.write(f"**Name:** {cliente['name']}")
                st.write(f"**Phone:** {cliente['phone']}")
                st.write(f"**Email:** {cliente['email']}")
                st.write(f"**Address:** {cliente['address']}")
                st.write(f"**Bank Account:** {cliente['bank_account']}")
                st.write(f"**Transfer:** {cliente['transfer']}")
                st.write(f"**PIN:** {cliente['pin']}")
                st.write(f"**Offer:** {cliente['offer']}")
                st.write(f"**Taxes:** {cliente['taxes']}")
                st.write(f"**SSN:** {cliente['ssn']}")
                st.write(f"**Tax ID:** {cliente['tax_id']}")
                st.write(f"**ITIN:** {cliente['itin']}")
                st.write(f"**Driving License:** {cliente['driving_license']}")
                st.write(f"**Driving License Expiration:** {cliente['driving_license_expiration']}")
                st.write(f"**Passport:** {cliente['passport']}")
                st.write(f"**Passport Expiration:** {cliente['passport_expiration']}")
                st.write(f"**Birthdate:** {cliente['birthdate']}")
                st.write(f"**Billing Card:** {cliente['billing_card']}")
                st.write(f"**Name on Card:** {cliente['name_card']}")
                st.write(f"**ZIP:** {cliente['zip']}")
                st.write(f"**CVV:** {cliente['cvv']}")
                st.write(f"**Card Expiration:** {cliente['expiration_card']}")
                st.write(f"**State:** {cliente['state']}")
                st.write(f"**City:** {cliente['city']}")

                if st.button(f"Editar Cliente {cliente['id']}"):
                    st.session_state['editar_cliente'] = cliente
                if st.button(f"Eliminar Cliente {cliente['id']}"):
                    delete_cliente(user, cliente['id'])
                    st.rerun()

        if 'editar_cliente' in st.session_state:
            cliente = st.session_state['editar_cliente']
            st.subheader(f"Editar Cliente ID: {cliente['id']}")
            cliente_data = {
                'name': st.text_input("Name", value=cliente['name']),
                'phone': st.number_input("Phone", value=cliente['phone'], min_value=0),
                'address': st.text_input("Address", value=cliente['address']),
                'email': st.text_input("Email", value=cliente['email']),
                'bank_account': st.number_input("Bank Account", value=cliente['bank_account'], min_value=0),
                'transfer': st.text_input("Transfer", value=cliente['transfer']),
                'pin': st.number_input("PIN", value=cliente['pin'], min_value=0),
                'offer': st.text_input("Offer", value=cliente['offer']),
                'taxes': st.text_input("Taxes", value=cliente['taxes']),
                'ssn': st.number_input("SSN", value=cliente['ssn'], min_value=0),
                'tax_id': st.number_input("Tax ID", value=cliente['tax_id'], min_value=0),
                'itin': st.number_input("ITIN", value=cliente['itin'], min_value=0),
                'driving_license': st.text_input("Driving License", value=cliente['driving_license']),
                'driving_license_expiration': st.date_input("Driving License Expiration", value=cliente['driving_license_expiration']),
                'passport': st.text_input("Passport", value=cliente['passport']),
                'passport_expiration': st.date_input("Passport Expiration", value=cliente['passport_expiration']),
                'birthdate': st.date_input("Birthdate", value=cliente['birthdate']),
                'billing_card': st.number_input("Billing Card", value=cliente['billing_card'], min_value=0),
                'name_card': st.text_input("Name on Card", value=cliente['name_card']),
                'zip': st.number_input("ZIP", value=cliente['zip'], min_value=0),
                'cvv': st.number_input("CVV", value=cliente['cvv'], min_value=0),
                'expiration_card': st.date_input("Card Expiration", value=cliente['expiration_card']),
                'state': st.text_input("State", value=cliente['state']),
                'city': st.text_input("City", value=cliente['city']),
                'creado_por': cliente['creado_por']
            }
            if st.button("Guardar Cambios"):
                update_cliente(user, cliente['id'], cliente_data)
                del st.session_state['editar_cliente']
                st.rerun()
    else:
        st.write("No hay clientes para mostrar.")

# Función para exportar los datos de clientes a CSV
def exportar_clientes_csv(user):
    if user['rol'] != 'gerente':
        st.error("Solo el Gerente puede exportar datos.")
        return

    # Obtener todos los clientes
    clientes = get_clientes(user)
    if not clientes:
        st.warning("No hay clientes para exportar.")
        return

    # Convertir la lista de clientes en un DataFrame
    df = pd.DataFrame(clientes)

    # Convertir el DataFrame a CSV
    csv = df.to_csv(index=False).encode('utf-8')

    # Botón para descargar el archivo CSV
    st.download_button(
        label="Exportar clientes a CSV",
        data=csv,
        file_name="clientes.csv",
        mime="text/csv",
    )

# Interfaz de inicio de sesión
def login():
    st.title("Inicio de Sesión")
    username = st.text_input("Usuario")
    password = st.text_input("Contraseña", type="password")

    if st.button("Iniciar Sesión"):
        user = authenticate_user(username, password)
        if user:
            # Generar un token de sesión
            session_token = generate_session_token()
            # Guardar el token en una cookie
            set_session_cookie(session_token)
            # Guardar el token en st.session_state
            st.session_state['user'] = user
            st.session_state['session_token'] = session_token
            st.success(f"Bienvenido, {user['username']}!")
            st.rerun()
        else:
            st.error("Usuario o contraseña incorrectos")

# Interfaz principal de la aplicación
def main_app():
    user = st.session_state.get('user')
    if not user:
        st.warning("Por favor inicia sesión para continuar")
        return

    st.title(f"Panel de {user['rol'].capitalize()}")
    st.write(f"Bienvenido, {user['username']}!")

    if st.sidebar.button("Cerrar Sesión"):
        # Eliminar la cookie
        delete_session_cookie()
        # Limpiar la sesión
        st.session_state.pop('user', None)
        st.session_state.pop('session_token', None)
        st.success("Has cerrado sesión correctamente.")
        st.rerun()

    # Menú de opciones
    menu = ["Ver Clientes", "Crear Cliente"]
    if user['rol'] == 'gerente':
        menu.append("Crear Usuario")
        menu.append("Eliminar Usuario")  # Nueva opción para el Gerente
        menu.append("Exportar Clientes a CSV")

    choice = st.sidebar.selectbox("Menú", menu)

    if choice == "Ver Clientes":
        view_edit_clientes_ui(user)
    elif choice == "Crear Cliente":
        create_cliente_ui(user)
    elif choice == "Crear Usuario":
        create_user_ui(user)
    elif choice == "Eliminar Usuario":
        delete_user_ui(user)
    elif choice == "Exportar Clientes a CSV":
        exportar_clientes_csv(user)

# Punto de entrada de la aplicación
def main():
    # Verificar la cookie al cargar la página
    get_session_cookie()

    if 'user' not in st.session_state:
        login()
    else:
        main_app()

if __name__ == "__main__":
    main()