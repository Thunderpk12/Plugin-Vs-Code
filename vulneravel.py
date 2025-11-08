
"""
Ficheiro de teste ABRANGENTE com vulnerabilidades REAIS e EDGE CASES.
O scanner DEVE detectar todos os problemas marcados com # VULN
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
import re
import json
import shlex

app = Flask(__name__)
logger = logging.getLogger(__name__)


# ==================== A03: SQL INJECTION ====================

def sql_direct_fstring(user_id):
    """VULN: SQL Injection via f-string"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # VULN
    return cursor.fetchall()


def sql_concatenation(user_name):
    """VULN: SQL Injection via concatenação"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + user_name + "'"  # VULN
    cursor.execute(query)
    return cursor.fetchall()


def sql_format_method(user_email):
    """VULN: SQL Injection via .format()"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE email = '{}'".format(user_email)  # VULN
    cursor.execute(query)
    return cursor.fetchall()


def sql_percent_formatting(user_role):
    """VULN: SQL Injection via % formatting"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE role = '%s'" % user_role  # VULN
    cursor.execute(query)
    return cursor.fetchall()


def sql_indirect_variable(search_term):
    """VULN: SQL Injection via variável intermediária"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    user_query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"  # VULN
    cursor.execute(user_query)  # VULN: variável intermediária tainted
    return cursor.fetchall()


def sql_weak_sanitization(user_input):
    """VULN: SQL Injection com sanitização FRACA"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cleaned = user_input.replace("'", "")  # VULN: sanitização fraca
    query = f"SELECT * FROM users WHERE name = '{cleaned}'"  # VULN
    cursor.execute(query)
    return cursor.fetchall()


def sql_ddl_command(table_name):
    """VULN: SQL Injection em DDL (mais grave que DML)"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"DROP TABLE {table_name}")  # VULN: DDL command
    return True


def sql_safe_parameterized(user_id):
    """SAFE: Uso correto de parâmetros"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # SAFE
    return cursor.fetchall()


def sql_safe_sanitized(user_id):
    """SAFE: Sanitização forte"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    safe_id = int(user_id)  # SAFE: conversão para int
    cursor.execute(f"SELECT * FROM users WHERE id = {safe_id}")  # SAFE
    return cursor.fetchall()


# ==================== A03: COMMAND INJECTION ====================

def cmd_os_system(hostname):
    """VULN: Command Injection via os.system"""
    os.system(f"ping -c 4 {hostname}")  # VULN


def cmd_subprocess_shell(filename):
    """VULN: Command Injection via subprocess com shell=True"""
    subprocess.run(f"cat {filename}", shell=True)  # VULN


def cmd_popen(directory):
    """VULN: Command Injection via Popen"""
    subprocess.Popen(f"ls -la {directory}", shell=True)  # VULN


def cmd_concatenation(user_command):
    """VULN: Command Injection via concatenação"""
    full_cmd = "echo " + user_command  # VULN
    os.system(full_cmd)  # VULN


def cmd_safe_list(filename):
    """SAFE: subprocess com lista (sem shell)"""
    subprocess.run(["cat", filename])  # SAFE


def cmd_safe_quote(user_path):
    """SAFE: uso de shlex.quote"""
    safe_path = shlex.quote(user_path)  # SAFE
    os.system(f"ls {safe_path}")  # SAFE


# ==================== A03: CODE INJECTION ====================

def code_eval(user_expr):
    """VULN: Code Injection via eval"""
    result = eval(user_expr)  # VULN
    return result


def code_exec(user_code):
    """VULN: Code Injection via exec"""
    exec(user_code)  # VULN


def code_compile(user_source):
    """VULN: Code Injection via compile"""
    code_obj = compile(user_source, '<string>', 'exec')  # VULN
    exec(code_obj)


def code_import(module_name):
    """VULN: Code Injection via __import__"""
    mod = __import__(module_name)  # VULN
    return mod


def code_safe_literal_eval(user_data):
    """SAFE: uso de ast.literal_eval"""
    import ast
    safe_data = ast.literal_eval(user_data)  # SAFE
    return safe_data


# ==================== A03: NOSQL INJECTION ====================

def nosql_where_operator(user_condition):
    """VULN: NoSQL Injection via $where"""
    client = pymongo.MongoClient()
    db = client.mydb
    query = {"$where": f"this.status == '{user_condition}'"}  # VULN
    return list(db.users.find(query))


def nosql_direct_filter(user_name):
    """VULN: NoSQL Injection via filtro direto"""
    client = pymongo.MongoClient()
    db = client.mydb
    filter_doc = f'{{"name": "{user_name}"}}'  # VULN
    return list(db.users.find(filter_doc))


def nosql_variable_filter(user_age):
    """VULN: NoSQL Injection via variável"""
    client = pymongo.MongoClient()
    db = client.mydb
    age_filter = {"age": {"$gt": user_age}}  # VULN: user_age não validado
    return list(db.users.find(age_filter))


def nosql_safe_query(user_id):
    """SAFE: Query com validação"""
    client = pymongo.MongoClient()
    db = client.mydb
    safe_id = int(user_id)  # SAFE
    return list(db.users.find({"_id": safe_id}))


# ==================== A03: LDAP INJECTION ====================

def ldap_filter_injection(username):
    """VULN: LDAP Injection em filtro"""
    conn = ldap.initialize('ldap://localhost')
    filter_str = f"(uid={username})"  # VULN
    conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, filter_str)


def ldap_dn_injection(user_cn):
    """VULN: LDAP Injection em DN"""
    conn = ldap.initialize('ldap://localhost')
    dn = f"cn={user_cn},ou=users,dc=example,dc=com"  # VULN
    conn.bind_s(dn, "password")


# ==================== A03: TEMPLATE INJECTION (SSTI) ====================

def ssti_template_string(user_input):
    """VULN: SSTI via Template com input"""
    from jinja2 import Template
    tmpl = Template(f"Hello {user_input}!")  # VULN
    return tmpl.render()


def ssti_render_template_string(template_str):
    """VULN: SSTI via render_template_string"""
    from flask import render_template_string
    return render_template_string(template_str)  # VULN


def ssti_from_string(user_template):
    """VULN: SSTI via Environment.from_string"""
    from jinja2 import Environment
    env = Environment()
    tmpl = env.from_string(user_template)  # VULN
    return tmpl.render()


def ssti_safe_sandboxed(user_data):
    """SAFE: Template com SandboxedEnvironment"""
    from jinja2.sandbox import SandboxedEnvironment
    env = SandboxedEnvironment()  # SAFE
    tmpl = env.from_string("Hello {{ name }}")
    return tmpl.render(name=user_data)  # SAFE: dados passados como contexto


# ==================== A03: XPATH INJECTION ====================

def xpath_query_injection(username):
    """VULN: XPath Injection"""
    import xml.etree.ElementTree as ET
    tree = ET.parse('users.xml')
    root = tree.getroot()
    query = f"//user[@name='{username}']"  # VULN
    return root.findall(query)


def xpath_iterfind_injection(user_id):
    """VULN: XPath via iterfind"""
    root = ET.parse('data.xml').getroot()
    xpath = f".//item[@id='{user_id}']"  # VULN
    return list(root.iterfind(xpath))


# ==================== A03: XML INJECTION / XXE ====================

def xxe_static_parser():
    """VULN: XXE com resolve_entities=True"""
    parser = ET.XMLParser(resolve_entities=True)  # VULN
    tree = ET.fromstring("<root></root>", parser=parser)
    return tree


def xxe_parse_untrusted(user_xml):
    """VULN: XXE parsing XML não confiável sem parser seguro"""
    tree = ET.fromstring(user_xml)  # VULN
    return ET.tostring(tree)


def xxe_iterparse(xml_file):
    """VULN: XXE via iterparse sem configuração segura"""
    for event, elem in ET.iterparse(xml_file):  # VULN
        print(elem.tag)


def xxe_safe_parser(xml_data):
    """SAFE: Parser com resolve_entities=False"""
    parser = ET.XMLParser(resolve_entities=False)  # SAFE
    tree = ET.fromstring(xml_data, parser=parser)
    return tree


# ==================== A03: HEADER INJECTION (CRLF) ====================

def header_injection_direct(redirect_url):
    """VULN: Header Injection via input direto"""
    response = make_response("Redirecting...")
    response.headers['Location'] = redirect_url  # VULN
    return response


def header_injection_fstring(custom_value):
    """VULN: Header Injection via f-string"""
    response = make_response("OK")
    response.headers['X-Custom'] = f"Value: {custom_value}"  # VULN
    return response


def header_safe_validated(user_agent):
    """SAFE: Header com validação"""
    response = make_response("OK")
    safe_ua = user_agent.replace('\r', '').replace('\n', '')  # SAFE
    response.headers['X-User-Agent'] = safe_ua
    return response


# ==================== A03: LOG INJECTION ====================

def log_injection_fstring(username):
    """VULN: Log Injection via f-string"""
    logging.error(f"Failed login for user: {username}")  # VULN


def log_injection_concatenation(error_msg):
    """VULN: Log Injection via concatenação"""
    logger.info("Error occurred: " + error_msg)  # VULN


def log_safe_structured(user_id, action):
    """SAFE: Logging estruturado"""
    logger.info("User action", extra={"user_id": user_id, "action": action})  # SAFE


# ==================== A09: LOGGING FAILURES ====================

def critical_delete_no_log(user_id):
    """VULN: Operação crítica SEM logging"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))  # VULN: sem log
    conn.commit()


def admin_action_no_log(target_user, new_role):
    """VULN: Ação administrativa SEM logging"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, target_user))  # VULN: sem log
    conn.commit()


def payment_transaction_no_log(amount, user_id):
    """VULN: Transação financeira SEM logging"""
    charge_credit_card(amount)  # VULN: sem log
    update_balance(user_id, amount)
    return True


def authenticate_user_no_log(username, password):
    """VULN: Autenticação SEM logging"""
    if check_credentials(username, password):  # VULN: sem log de sucesso/falha
        return True
    return False


def reset_password_no_log(user_email, new_password):
    """VULN: Reset de password SEM logging"""
    update_password(user_email, new_password)  # VULN: sem log
    return True


def login_with_logging(username):
    """SAFE: Login COM logging apropriado"""
    if authenticate(username):
        logging.warning(f"Successful login for user: {username}")  # SAFE
        return True
    logging.warning(f"Failed login attempt for user: {username}")  # SAFE
    return False


def delete_with_logging(user_id, admin_id):
    """SAFE: Operação crítica COM logging"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    logging.warning(f"User {user_id} deleted by admin {admin_id}")  # SAFE
    return True


# ==================== A09: SENSITIVE DATA IN LOGS ====================

def log_password(username, password):
    """VULN: Password em log"""
    logging.info(f"Login attempt - user: {username}, password: {password}")  # VULN: password em log


def log_credit_card(card_number, user_id):
    """VULN: Cartão de crédito em log"""
    logger.debug(f"Processing payment for user {user_id} with card {card_number}")  # VULN: card em log


def log_api_key(api_key):
    """VULN: API key em log"""
    logging.error(f"Invalid API key: {api_key}")  # VULN: api_key em log


def log_token(auth_token):
    """VULN: Token em log"""
    logger.info(f"Authentication token received: {auth_token}")  # VULN: token em log


def log_ssn(social_security):
    """VULN: SSN em log"""
    logging.warning(f"SSN verification failed: {social_security}")  # VULN: ssn em log


def log_safe_masked(card_number):
    """SAFE: Dados mascarados em log"""
    masked = f"****{card_number[-4:]}"
    logging.info(f"Payment processed with card ending in {masked}")  # SAFE


# ==================== A09: INAPPROPRIATE LOG LEVELS ====================

def security_event_debug_level(username):
    """VULN: Evento de segurança em DEBUG"""
    if authenticate(username):
        logging.debug(f"Admin user {username} logged in")  # VULN: deveria ser warning/info
        return True
    return False


def critical_operation_info_level(table_name):
    """VULN: Operação crítica em INFO"""
    logging.info(f"Dropping table {table_name}")  # VULN: deveria ser warning/critical
    drop_table(table_name)


def payment_debug_level(amount, user):
    """VULN: Transação financeira em DEBUG"""
    logging.debug(f"Processing payment of ${amount} for {user}")  # VULN: deveria ser info/warning
    process_payment(amount, user)


# ==================== A09: UNLOGGED EXCEPTIONS ====================

def silent_exception_handler(user_input):
    """VULN: Exceção sem logging"""
    try:
        result = risky_operation(user_input)
        return result
    except Exception as e:
        return None  # VULN: exceção não logada


def exception_with_pass(data):
    """VULN: Exceção com pass"""
    try:
        process_data(data)
    except ValueError:
        pass  # VULN: pass sem logging (mas pode ser intencional)


def exception_logged_object(user_id):
    """VULN: Logging do objeto de exceção completo"""
    try:
        critical_operation(user_id)
    except Exception as e:
        logging.error(f"Error: {e}")  # VULN: pode expor stack trace sensível


def exception_safe_logged():
    """SAFE: Exceção COM logging apropriado"""
    try:
        risky_operation()
    except Exception as e:
        logging.error("Operation failed", exc_info=False)  # SAFE
        return None


def exception_safe_reraise():
    """SAFE: Exceção re-lançada (não precisa log aqui)"""
    try:
        risky_operation()
    except Exception:
        raise  # SAFE: propaga a exceção


# ==================== EDGE CASES ====================

def multiple_taint_sources(param1, param2):
    """VULN: Múltiplas sources tainted"""
    user_input = request.args.get('input')  # SOURCE 1
    user_data = request.json.get('data')  # SOURCE 2
    
    combined = f"{user_input} - {user_data}"  # VULN: ambos tainted
    os.system(f"echo {combined}")  # VULN


def taint_through_dict(search_params):
    """VULN: Taint propagado através de dict"""
    filters = {}
    filters['name'] = request.args.get('name')  # VULN: dict fica tainted
    
    conn = sqlite3.connect('database.db')
    query = f"SELECT * FROM users WHERE name = '{filters['name']}'"  # VULN
    conn.execute(query)


def taint_through_function_return():
    """VULN: Taint propagado via return de função"""
    user_value = get_user_input()  # Função que retorna tainted
    os.system(f"process {user_value}")  # VULN


def get_user_input():
    """Helper que retorna dado tainted"""
    return request.args.get('value')  # SOURCE


def nested_sanitization_bypass(user_input):
    """VULN: Bypass de sanitização por nested encoding"""
    cleaned = user_input.replace("'", "''")  # Weak sanitization
    query = f"SELECT * FROM users WHERE name = '{cleaned}'"  # VULN: ainda vulnerável
    return query


# ==================== HELPER FUNCTIONS ====================

def charge_credit_card(amount):
    pass

def update_balance(user_id, amount):
    pass

def check_credentials(username, password):
    return True

def authenticate(username):
    return True

def update_password(user_email, new_password):
    pass

def drop_table(table_name):
    pass

def process_payment(amount, user):
    pass

def risky_operation(data=None):
    pass

def process_data(data):
    pass

def critical_operation(user_id):
    pass


if __name__ == "__main__":
    print("Este ficheiro contém vulnerabilidades intencionais para teste.")
    print("Total esperado: ~50+ vulnerabilidades detectáveis")
    print("\nBreakdown esperado:")
    print("- A03 (Injection): ~40 vulnerabilidades")
    print("  - SQL Injection: ~10")
    print("  - Command Injection: ~7")
    print("  - Code Injection: ~4")
    print("  - NoSQL Injection: ~3")
    print("  - LDAP Injection: ~2")
    print("  - SSTI: ~3")
    print("  - XPath: ~2")
    print("  - XXE: ~3")
    print("  - Header Injection: ~2")
    print("  - Log Injection: ~2")
    print("  - Edge cases: ~3")
    print("\n- A09 (Logging): ~15 vulnerabilidades")
    print("  - Missing logs: ~5")
    print("  - Sensitive data: ~5")
    print("  - Wrong levels: ~3")
    print("  - Unlogged exceptions: ~3")