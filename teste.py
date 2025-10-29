# Ficheiro de teste para o scanner de vulnerabilidades SAST em Python.
# Contém exemplos de código vulnerável e seguro para validar a deteção.

import os
import subprocess
import sqlite3
import logging
from lxml import etree
from flask import Flask, request, Response, render_template_string
import pymongo # Apenas para simular a sintaxe
import ldap # Apenas para simular a sintaxe

# --- Simulação de Input Externo ---
# Em aplicações reais, estes dados viriam de fontes não confiáveis.
def get_user_input(source: str) -> str:
    if source == 'username':
        return "admin' OR '1'='1"
    if source == 'user_id':
        return "123"
    if source == 'filename':
        return "user_profile.txt; ls -la"
    if source == 'ldap_filter':
        return ")(uid=*))(|(isMemberOf=cn=admin,ou=groups,dc=example,dc=com)"
    if source == 'redirect_url':
        return "https://trusted.com\r\nInjected-Header: InjectedValue"
    if source == 'log_info':
        return "user_login_failed\nDELETING CRITICAL FILES..."
    return "generic_user_input"

# --- Configuração ---
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s - %(message)s')
db_connection = sqlite3.connect(':memory:')
db_cursor = db_connection.cursor()
app = Flask(__name__)

# 1. SQL INJECTION (OWASP A03: Injection)
def sql_injection_examples():
    user_id = get_user_input('user_id')
    username = get_user_input('username')

    # VULNERÁVEL: f-string
    query_fstring = f"SELECT * FROM users WHERE username = '{username}'"
    db_cursor.execute(query_fstring)

    # VULNERÁVEL: Concatenação
    query_concat = "SELECT data FROM items WHERE owner_id = " + user_id
    db_cursor.execute(query_concat)

    # VULNERÁVEL: Formatação com %
    query_percent = "UPDATE users SET is_admin = 1 WHERE username = '%s'" % username
    db_cursor.execute(query_percent)

    # VULNERÁVEL: .format()
    query_format = "DELETE FROM logs WHERE user_id = '{}'".format(user_id)
    db_cursor.execute(query_format)

    # SEGURO: Query parametrizada (não deve ser detetado)
    safe_query = "SELECT * FROM users WHERE username = ?"
    db_cursor.execute(safe_query, (username,))

# 2. COMMAND INJECTION (OWASP A03: Injection)
def command_injection_examples():
    filename = get_user_input('filename')

    # VULNERÁVEL: os.system com f-string
    os.system(f"cat /path/to/files/{filename}")

    # VULNERÁVEL: subprocess.run com concatenação e shell=True
    command = "ping -c 4 " + filename
    subprocess.run(command, shell=True)

    # SEGURO: subprocess.run sem shell=True (não deve ser detetado)
    subprocess.run(["ls", "-l", f"/path/{filename}"])

# 3. CODE INJECTION (OWASP A03: Injection)
def code_injection_examples():
    user_formula = "2 * (10 + 5)" # Simula input que deveria ser seguro
    malicious_code = "__import__('os').system('echo vulnerable')"

    # VULNERÁVEL: eval() com input de variável
    result = eval(malicious_code)
    print(result)

    # VULNERÁVEL: exec()
    exec(f"print('executing: {malicious_code}')")

# 4. LDAP INJECTION (OWASP A03: Injection)
def ldap_injection_example():
    user_search = get_user_input('ldap_filter')
    base_dn = "ou=users,dc=example,dc=com"
    
    # VULNERÁVEL: Filtro de busca construído com concatenação
    search_filter = "(&(uid=" + user_search + ")(objectClass=person))"
    
    # Simulação da chamada vulnerável
    # ldap_connection.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)

# 5. NOSQL INJECTION (OWASP A03: Injection)
def nosql_injection_example():
    # Simulação de uma coleção MongoDB
    mongo_collection = pymongo.MongoClient().db.users
    js_code = get_user_input('js_code') # Ex: "'; return true; //"

    # VULNERÁVEL: Uso do operador $where com input não validado
    query = {"$where": f"this.name == '{js_code}'"}
    mongo_collection.find(query)

    # SEGURO: Uso de dicionário estático (não deve ser detetado)
    mongo_collection.find({"name": "user123"})

# 6. TEMPLATE INJECTION (SSTI) (OWASP A03: Injection)
def template_injection_example():
    user_template = "Hello {{ config.SECRET_KEY }}" # Input malicioso

    # VULNERÁVEL: render_template_string com variável
    # Dentro de um contexto Flask, isto seria perigoso
    with app.app_context():
        render_template_string(f"<p>{user_template}</p>")

# 7. XPATH INJECTION (OWASP A03: Injection)
def xpath_injection_example():
    xml_string = "<users><user name='validuser'><role>guest</role></user></users>"
    root = etree.fromstring(xml_string)
    username = "' or '1'='1"

    # VULNERÁVEL: Construção de query XPath com f-string
    xpath_query = f"//user[@name='{username}']"
    result = root.xpath(xpath_query)
    print(f"XPath result: {result}")

# 8. XML INJECTION (XXE) (OWASP A03: Injection)
def xxe_injection_example():
    malicious_xml = """<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <foo>&xxe;</foo>"""

    # VULNERÁVEL: Parser configurado para resolver entidades externas
    parser = etree.XMLParser(resolve_entities=True)
    etree.fromstring(malicious_xml, parser=parser)

    # SEGURO: Parser padrão (não deve ser detetado)
    safe_parser = etree.XMLParser(resolve_entities=False)
    etree.fromstring(b"<root>safe</root>", parser=safe_parser)

# 9. HEADER INJECTION (CRLF) (OWASP A03: Injection)
def header_injection_example():
    redirect_url = get_user_input('redirect_url')
    
    # VULNERÁVEL: Valor de cabeçalho vindo de input externo
    response = Response()
    response.headers['Location'] = redirect_url
    return response

# 10. LOG INJECTION
def log_injection_example():
    user_info = get_user_input('log_info')

    # VULNERÁVEL: Logging de informação não sanitizada
    logging.info(f"User information: {user_info}")

    # Padrão mais seguro (ainda pode ser vulnerável, mas melhor)
    # Idealmente, o input deveria ser sanitizado antes.
    logging.info("User information: %s", user_info.replace('\n', ' ').replace('\r', ''))


if __name__ == "__main__":
    print("Executando ficheiro de teste de vulnerabilidades...")
    
    # Chamar todas as funções para garantir que o código é sintaticamente válido
    sql_injection_examples()
    command_injection_examples()
    code_injection_examples()
    xpath_injection_example()
    log_injection_example()
    
    # As restantes funções são para análise estática e não precisam de execução real
    
    print("Execução do teste concluída. Analise este ficheiro com o scanner.")
   