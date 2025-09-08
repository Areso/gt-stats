from flask import Flask, request
import json
import mysql.connector
import math
import toml
import copy
import sys
import base64

class DBConnect:
    def __init__(self, cluster, salt):
        config   = final_config["clusters"][cluster]
        password = decipher(config["password"], salt)
        self.con = mysql.connector.connect(
            host      = config["host"],
            user      = config["user"],
            passwd    = password,
            database  = config["db"],
            port      = config["port"],
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


def get_obj_stats (cluster, db, table):
    global final_config
    if not cluster in final_config["clusters"]:
        return 0, 0, 400
    if db is not None:
        if not db in final_config["clusters"][cluster]["dbs"]:
            return 0, 0, 400
    if table is None:
        return 0, 0, 400
    global salt
    db_con = DBConnect(cluster, salt)
    if db is None:
        db_con.cur.execute("""SELECT table_rows, 
                                     data_length,
                                     index_length
                              FROM  information_schema.tables
                              WHERE table_name = %(table_name)s
                              ORDER BY (data_length + index_length) DESC
                              LIMIT 1""",
                              {"table_name":   table})
    else:
        db_con.cur.execute("""SELECT table_rows, 
                                     data_length,
                                     index_length
                              FROM information_schema.tables
                              WHERE table_name = %(table_name)s
                              AND table_schema= %(table_schema)s;""",
                              {"table_name":   table,
                               "table_schema": db})
    myresult = db_con.cur.fetchall()
    db_con.close()
    if len(myresult)>0:
        data_size_b  = myresult[0][1]
        index_size_b = myresult[0][2]
        size_in_mb = math.ceil( (data_size_b+index_size_b) / (1024*1024) )
        rows_number  = myresult[0][0]
        return rows_number, size_in_mb, 200
    else:
        return 0, 0, 404

@app.route('/check_stats', methods=['POST','OPTIONS'])
def check_stats():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    reqdata            = request.get_data().decode()
    reqobj             = json.loads(reqdata)
    cluster: str       = reqobj.get("cluster",None)
    if cluster is not None:
        cluster = cluster.lower()
    db:      str       = reqobj.get("db",None)
    if db is not None:
        db      = db.lower()
    table:   str       = reqobj.get("table",None)
    if table is not None:
        table   = table.lower()
    obj_stats          = get_obj_stats(cluster, db, table)
    return obj_stats, 200, cheaders_p


@app.route('/__cipher_pass', methods=['POST','OPTIONS'])
def cipher_pass():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    reqdata            = request.get_data().decode()
    reqobj             = json.loads(reqdata)
    password: str      = reqobj.get("pass",None)
    if password is None:
        return "password field isnot provided", 400, cheaders_p
    return cipher(password,salt), 200, cheaders_p


@app.route('/__decipher_pass', methods=['POST','OPTIONS'])
def decipher_pass():
    if request.method == 'OPTIONS':
        return "", 204, cheaders_p
    reqdata            = request.get_data().decode()
    reqobj             = json.loads(reqdata)
    password: str      = reqobj.get("pass",None)
    if password is None:
        return "password field isnot provided", 400, cheaders_p
    return decipher(password,salt), 200, cheaders_p


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
        return content
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file '{file_path}': {e}")
        sys.exit(1)


config       = toml.load("config.toml")
secrets      = toml.load("secrets.toml")
final_config = deep_merge(config, secrets)
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
            port =final_config["app"]["app_port"])
