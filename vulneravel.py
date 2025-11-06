"""
Ficheiro de teste com exemplos de código VULNERÁVEL.
O scanner DEVE encontrar problemas neste ficheiro.
"""

import sqlite3
import os
import subprocess
from flask import Flask, request, make_response
import ldap
import pymongo
from jinja2 import Template
import xml.etree.ElementTree as ET
import logging

app = Flask(__name__)

# ==================== VULNERABILIDADES REAIS ====================

@app.route("/vulnerable_test")
def vulnerable_test():
    """Rota principal para obter dados 'tainted' (infectados)"""
    
    # --- SOURCES ---
    # Todos estes dados são 'tainted'
    user_id = request.args.get("id")
    user_name = request.args.get("name")
    user_input = request.args.get("input")
    user_xml = request.data
    user_header = request.args.get("header")

    # --- SINKS ---
    # Chamadas a funções vulneráveis com dados 'tainted'
    
    try:
        sql_vulnerable(user_id)
    except Exception as e:
        print(f"Error SQL: {e}")

    try:
        command_vulnerable(user_input)
    except Exception as e:
        print(f"Error Command: {e}")

    try:
        code_vulnerable(user_input)
    except Exception as e:
        print(f"Error Code: {e}")

    try:
        ldap_vulnerable(user_name)
    except Exception as e:
        print(f"Error LDAP: {e}")
        
    try:
        nosql_vulnerable(user_input)
    except Exception as e:
        print(f"Error NoSQL: {e}")

    try:
        ssti_vulnerable(user_name)
    except Exception as e:
        print(f"Error SSTI: {e}")

    try:
        xpath_vulnerable(user_name)
    except Exception as e:
        print(f"Error XPath: {e}")

    try:
        xxe_vulnerable_dynamic(user_xml)
    except Exception as e:
        print(f"Error XXE Dynamic: {e}")

    try:
        log_vulnerable(user_name)
    except Exception as e:
        print(f"Error Log: {e}")
        
    try:
        xxe_vulnerable_static()
    except Exception as e:
        print(f"Error XXE Static: {e}")

    try:
        return header_vulnerable(user_header)
    except Exception as e:
        print(f"Error Header: {e}")

    return "Vulnerable functions executed."


# --- Funções SINK (Vulneráveis) ---

def sql_vulnerable(user_id):
    """SQL VULNERÁVEL: formatação de string"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # VULNERÁVEL: f-string injeta 'user_id'
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()


def command_vulnerable(user_input):
    """Command VULNERÁVEL: os.system"""
    # VULNERÁVEL: os.system com input
    os.system(f"ping -c 4 {user_input}")


def code_vulnerable(user_input):
    """Code VULNERÁVEL: eval()"""
    # VULNERÁVEL: eval() em input
    result = eval(user_input)
    return str(result)


def ldap_vulnerable(user_name):
    """LDAP VULNERÁVEL: f-string em filtro"""
    conn = ldap.initialize('ldap://localhost')
    # VULNERÁVEL: f-string no filtro
    filter_str = f"(uid={user_name})"
    conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, filter_str)


def nosql_vulnerable(user_input):
    """NoSQL VULNERÁVEL: $where com f-string"""
    client = pymongo.MongoClient()
    db = client.mydb
    # VULNERÁVEL: $where com input
    query = {"$where": f"this.name == '{user_input}'"}
    return db.users.find(query)


def ssti_vulnerable(user_name):
    """SSTI VULNERÁVEL: Template criado a partir de input"""
    # VULNERÁVEL: Template() usa input
    template = Template(f"Hello {user_name}, welcome!")
    return template.render()


def xpath_vulnerable(user_name):
    """XPath VULNERÁVEL: f-string na query"""
    root = ET.parse('users.xml').getroot()
    # VULNERÁVEL: f-string na query xpath
    xpath_query = f"//user[@name='{user_name}']"
    return root.xpath(xpath_query)


def xxe_vulnerable_static():
    """XXE VULNERÁVEL: resolve_entities=True"""
    # VULNERÁVEL: Configuração estática perigosa
    parser = ET.XMLParser(resolve_entities=True)
    tree = ET.fromstring("<root></root>", parser=parser)
    return tree


def xxe_vulnerable_dynamic(user_xml):
    """XXE VULNERÁVEL: parsing de input sem parser seguro"""
    # VULNERÁVEL: 'fromstring' sem o 'parser=...' seguro
    tree = ET.fromstring(user_xml)
    return ET.tostring(tree)


def header_vulnerable(user_input):
    """Header VULNERÁVEL: input em header"""
    response = make_response("OK")
    # VULNERÁVEL: input 'tainted' usado no valor do header
    response.headers['X-Custom-Location'] = user_input
    return response


def log_vulnerable(user_name):
    """Log VULNERÁVEL: input em log"""
    # VULNERÁVEL: input 'tainted' em f-string de log
    logging.error(f"Failed login attempt for user: {user_name}")


if __name__ == "__main__":
   
    app.run(debug=True)