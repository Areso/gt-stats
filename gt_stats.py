from flask import Flask, request
import json
import mysql.connector
import math
import toml
import copy
import sys
import base64
import re

class DBConnect:
    def __init__(self, cluster, salt: str, db: str="mysql"):
        if salt is not None:
            password = decipher(cluster.get("pwd"), salt)
        else:
            password = cluster.get("pwd")
        self.con = mysql.connector.connect(
            host      = cluster.get("host"),
            user      = cluster.get("user"),
            passwd    = password,
            database  = db,
            port      = cluster.get("port"),
            connection_timeout=30,
            auth_plugin = 'mysql_native_password',
            time_zone = '+00:00',
            autocommit= True
        )
        self.cur = self.con.cursor()
    def close(self):
        self.cur.close()
        self.con.close()

app = Flask(__name__)

def cipher(msg: str, salt: str) -> str:
    m = msg.encode("utf-8")
    k = salt.encode("utf-8")
    x = bytes([m[i] ^ k[i % len(k)] for i in range(len(m))])
    return base64.b64encode(x).decode("utf-8")


def decipher(ciphered_msg_b64: str, salt: str) -> str:
    x = base64.b64decode(ciphered_msg_b64)
    k = salt.encode("utf-8")
    m = bytes([x[i] ^ k[i % len(k)] for i in range(len(x))])
    return m.decode("utf-8")


def get_databases(cluster):
    db_con = DBConnect(cluster, salt=None)
    try:
        db_con.cur.execute("""SHOW DATABASES""")
        dbs = db_con.cur.fetchall()
        if not dbs:
            return [], 404
        return dbs, 200
    finally:
        db_con.close()


def get_tables(cluster, db):
    global final_config
    if not cluster in final_config["clusters"]:
        return [], 400
    db_con = DBConnect(cluster, salt, db)
    try:
        db_con.cur.execute("""SHOW TABLES""")
        tables = db_con.cur.fetchall()
        if not tables:
            return [], 404
        return tables, 200
    finally:
        db_con.close()


def get_obj_stats (cluster, db, table):
    global final_config
    if not cluster in final_config["clusters"]:
        return 0, 0, 400
    if table is None:
        return 0, 0, 400
    global salt
    db_con = DBConnect(cluster, salt)
    try:
        if db is None:
            query = """
                SELECT table_rows, data_length, index_length
                FROM information_schema.tables
                WHERE table_name = %(table_name)s
                ORDER BY (data_length + index_length) DESC
                LIMIT 1
            """
            params = {"table_name": table}
        else:
            query = """
                SELECT table_rows, data_length, index_length
                FROM information_schema.tables
                WHERE table_name = %(table_name)s
                  AND table_schema = %(table_schema)s
            """
            params = {"table_name": table, "table_schema": db}

        db_con.cur.execute(query, params)

        # Debug: print executed query
        if True:
            if hasattr(db_con.cur, "statement"):   # MySQL
                print("Executed query:", db_con.cur.statement)
            else:
                print("Executed query text unavailable (no attribute for this driver)")

        row = db_con.cur.fetchone()
        db_con.cur.execute(query, params)

        row = db_con.cur.fetchone()
        if not row:
            return 0, 0, 404

        rows_number  = int(row[0] or 0)
        data_size_b  = int(row[1] or 0)
        index_size_b = int(row[2] or 0)
        size_in_mb   = math.ceil((data_size_b + index_size_b) / (1024 * 1024))
        return rows_number, size_in_mb, 200
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        db_con.close()


@app.route('/databases_list', methods=['POST','OPTIONS'])
def databases_list():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    payload = request.get_json(force=True, silent=True)
    if payload is None:
        return {"error": "invalid JSON"}, 400, cheaders_p
    cluster = (payload.get("cluster") or "").lower()
    if cluster=="":
        return {"error": "cluster name didn't provided"}, 400, cheaders_p
    
    clusters = list(final_config["clusters"].keys())
    if cluster not in clusters:
        return {"error": "cluster not found in clusters.toml"}, 404, cheaders_p

    cluster_obj = final_config["clusters"][cluster]
    databases, status = get_databases(cluster_obj)
    return databases, status, cheaders_p


@app.route('/tables_list', methods=['POST','OPTIONS'])
def tables_list():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    payload = request.get_json(force=True, silent=True)
    if payload is None:
        return {"error": "invalid JSON"}, 400, cheaders_p
    cluster = (payload.get("cluster") or "").lower()
    db = (payload.get("db") or "").lower()
    tables, status = get_tables(cluster, db)
    return tables, status, cheaders_p


_ident = re.compile(r"^[A-Za-z0-9_]+$")
def ident(name: str) -> str:
    if not _ident.match(name):
        raise ValueError(f"Invalid identifier: {name!r}")
    return f"`{name}`"  # backtick-quote identifier

def get_migrations(cluster, db, migrations_table):
    global final_config
    if not cluster in final_config["clusters"]:
        return [], 400
    db_con = DBConnect(cluster, salt)
    try:
        try:
            sql = f"SELECT * FROM {ident(db)}.{ident(migrations_table)}"
            db_con.cur.execute(sql)
            rows = db_con.cur.fetchall()
            return rows, 0  
        except mysql.connector.errors.ProgrammingError as e:
            # 1146: Table doesn't exist
            if getattr(e, "errno", None) == 1146:
                return [], -2
            else:
                return [], -1
        #finally:
        #    db_con.cur.close()
    finally:
        db_con.close()


@app.route('/migrations_read', methods=['POST','OPTIONS'])
def migrations_read():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    payload = request.get_json(force=True, silent=True)
    if payload is None:
        return {"error": "invalid JSON"}, 400, cheaders_p
    cluster = payload.get("cluster", None).lower()
    if cluster is None:
        return {"error": "cluster value is not provided"}, 400, cheaders_p
    db      = payload.get("db", None).lower()
    if db is None:
        return {"error": "db value is not provided"}, 400, cheaders_p
    
    migrations_table   = "migrations"
    migrations, status = get_migrations(cluster, db, migrations_table)
    if status == -1:
        return {"error": "db value is not provided"}, 400, cheaders_p
    return migrations, 200


@app.route('/known_clusters_list', methods=['POST','OPTIONS'])
def known_clusters_list():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    clusters = list(final_config["clusters"].keys())
    return clusters, 200

@app.route('/healthcheck', methods=['GET','POST','OPTIONS'])
def healthcheck():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    return "OK", 200

@app.route('/is_it_safe_to_proceed', methods=['POST','OPTIONS'])
def is_safe():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    payload = request.get_json(force=True, silent=True)
    if payload is None:
        return {"error": "invalid JSON"}, 400, cheaders_p
    cluster = (payload.get("cluster") or "").lower()
    db      = payload.get("db", "mysql").lower()
    table   = payload.get("table")

    rows, size_mb, status = get_obj_stats(cluster, db, table)

    if size_mb >= final_config["app"]["t_size_threshold_mb"]:
        return {"safe_to_proceed": "false"}, status, cheaders_p

    if rows >= final_config["app"]["t_size_threshold_rows"]:
        return {"safe_to_proceed": "false"}, status, cheaders_p

    return {"safe_to_proceed": "true"}, status, cheaders_p

@app.route('/table_stats', methods=['POST','OPTIONS'])
def check_stats():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    payload = request.get_json(force=True, silent=True)
    if payload is None:
        return {"error": "invalid JSON"}, 400, cheaders_p
    cluster = (payload.get("cluster") or "").lower()
    db      = payload.get("db", "mysql").lower()
    table   = payload.get("table")

    rows, size_mb, status = get_obj_stats(cluster, db, table)
    return {"rows": rows, "size_mb": size_mb}, status, cheaders_p


@app.route('/__cipher_pass', methods=['POST','OPTIONS'])
def cipher_pass():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    payload = request.get_json(force=True, silent=True)
    if payload is None:
        return {"error": "invalid JSON"}, 400, cheaders_p
    password = payload.get("pass")
    if not isinstance(password, str):
        return {"error": "pass is required"}, 400, cheaders_p
    try:
        return cipher(password, salt), 200, cheaders_p
    except ValueError as e:
        return {"error": str(e)}, 400, cheaders_p

@app.route('/__decipher_pass', methods=['POST','OPTIONS'])
def decipher_pass():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    payload = request.get_json(force=True, silent=True)
    if payload is None:
        return {"error": "invalid JSON"}, 400, cheaders_p
    b64txt = payload.get("pass")
    if not isinstance(b64txt, str):
        return {"error": "pass is required (base64)"}, 400, cheaders_p
    try:
        return decipher(b64txt, salt), 200, cheaders_p
    except ValueError as e:
        return {"error": str(e)}, 400, cheaders_p


def deep_merge(base, override):
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in merged 
            and isinstance(merged[key], dict) 
            and isinstance(value, dict)
        ):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged

def read_file_content(file_path):
    """
    Reads the content of a file and returns it as a string.
    
    :param file_path: Path to the file to be read.
    :return: String content of the file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        if content=="":
            print(f"Salt is empty file. Put some data")
            sys.exit(1)
        return content
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file '{file_path}': {e}")
        sys.exit(1)


config       = toml.load("config.toml")
secrets      = toml.load("clusters.toml")
final_config = deep_merge(config, secrets)

if final_config.get("salt_location", None) is not None:
    salt: str    = read_file_content(final_config["app"]["salt_location"]).strip()

cheaders_p   = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",                    # change to concrete origin if using cookies
    "Access-Control-Allow-Methods": "POST, OPTIONS",       # string, not list
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Expose-Headers": "Content-Disposition",  # avoid "*"; list real ones if you need any
    "Access-Control-Max-Age": "600",
}

if __name__ == '__main__':
    app.run(debug=final_config["app"]["debug"], 
            port =final_config["app"]["app_port"],
            host=final_config["app"]["host"])
