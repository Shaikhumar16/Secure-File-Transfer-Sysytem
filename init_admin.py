# Create an admin user directly in the database. Uses environment variables from .env
import os, sys
from dotenv import load_dotenv
import pymysql, bcrypt

load_dotenv()
def get_db():
    return pymysql.connect(
        host=os.environ.get('MYSQL_HOST','localhost'),
        port=int(os.environ.get('MYSQL_PORT',3306)),
        user=os.environ.get('MYSQL_USER','root'),
        password=os.environ.get('MYSQL_PASSWORD',''),
        database=os.environ.get('MYSQL_DATABASE','file_transfer_db'),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )
def create_admin(username, password):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)", (username, pw_hash, 'admin'))
    conn.close()
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python init_admin.py <username> <password>')
        sys.exit(1)
    create_admin(sys.argv[1], sys.argv[2])
    print('Admin user created.')    
