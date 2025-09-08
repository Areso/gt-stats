from flask import Flask, request
import json
import mysql.connector
import math
import toml
import copy
import sys

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
            connection_timeout=86400,
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
    """Cipher a message with a salt using XOR."""
    extended_salt = (salt * (len(msg) // len(salt) + 1))[:len(msg)]
    return "".join(chr(ord(c) ^ ord(s)) for c, s in zip(msg, extended_salt))

def decipher(ciphered_msg: str, salt: str) -> str:
    """Decipher a message with a salt using XOR."""
    # XOR with the same salt restores the original msg
    extended_salt = (salt * (len(ciphered_msg) // len(salt) + 1))[:len(ciphered_msg)]
    return "".join(chr(ord(c) ^ ord(s)) for c, s in zip(ciphered_msg, extended_salt))

def get_obj_stats (cluster, db, table):
    global final_config
    if not cluster in final_config["clusters"]:
        return {-1, -1}
    if not db in final_config["clusters"][cluster]["dbs"]:
        return {-1, -1}
    if table is None:
        return {-1, -1}
    global salt
    db_con = DBConnect(cluster, salt)
    if db is None:
        db_con.cur.execute("""SELECT table_rows, 
                                     data_length,
                                     index_length
                              FROM  information_schema.tables
                              WHERE table_name = %(table_name)s""",
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
        return {rows_number, size_in_mb}
    else:
        return {0,0}

@app.route('/check_stats', methods=['POST','OPTIONS'])
def check_stats():
    reqdata            = request.get_data().decode()
    reqobj             = json.loads(reqdata)
    cluster: str       = reqobj.get("cluster",None).lower()
    db:      str       = reqobj.get("db",None).lower()
    table:   str       = reqobj.get("table",None).lower()
    obj_stats          = get_obj_stats(cluster, db, table)
    return obj_stats, 200, cheaders_p


@app.route('/__cipher_pass', methods=['POST','OPTIONS'])
def cipher_pass():
    reqdata            = request.get_data().decode()
    reqobj             = json.loads(reqdata)
    password: str      = reqobj.get("pass",None)
    return cipher(password,salt), 200, cheaders_p


@app.route('/__decipher_pass', methods=['POST','OPTIONS'])
def decipher_pass():
    reqdata            = request.get_data().decode()
    reqobj             = json.loads(reqdata)
    password: str      = reqobj.get("pass",None)
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
    
if __name__ == '__main__':
    config       = toml.load("config.toml")
    secrets      = toml.load("secrets.toml")
    final_config = deep_merge(config, secrets)
    salt: str    = read_file_content(final_config["app"]["salt_location"])
    myconfig     = {}
    cheaders_p   = {
        "Content-Type": "application/json; charset=utf-8",
        "Access-Control-Allow-Origin": "*",                    # change to concrete origin if using cookies
        "Access-Control-Allow-Methods": "POST, OPTIONS",       # string, not list
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Expose-Headers": "Content-Disposition",  # avoid "*"; list real ones if you need any
        "Access-Control-Max-Age": "600",
    }
    app.run(debug=final_config["app"]["debug"], 
            port =final_config["app"]["app_port"])
