import sqlite3
import subprocess
import os

# ============================================
# SQL INJECTION TESTS
# ============================================

def sql_safe_examples():
    """Exemplos SEGUROS - NÃO devem ser detectados"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Literal pura - SEGURO
    cursor.execute("SELECT * FROM users")
    
    # Query parametrizada - SEGURO
    user_id = 123
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    
    # Outra forma de parametrização - SEGURO
    cursor.execute("SELECT * FROM users WHERE name = :name", {"name": "João"})


def sql_vulnerable_examples():
    """Exemplos VULNERÁVEIS - DEVEM ser detectados"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    user_input = input("Enter username: ")
    user_id = "123"
    
    # VULNERÁVEL - f-string
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
    
    # VULNERÁVEL - concatenação
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    
    # VULNERÁVEL - format()
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(user_input))
    
    # VULNERÁVEL - % formatting
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    
    # VULNERÁVEL - variável direta
    table_name = user_input
    cursor.execute(table_name)


# ============================================
# COMMAND INJECTION TESTS
# ============================================

def command_safe_examples():
    """Exemplos SEGUROS - NÃO devem ser detectados"""
    
    # Comando literal - SEGURO
    os.system("ls -la")
    
    # Lista de argumentos - SEGURO
    subprocess.run(["ls", "-la"])
    subprocess.call(["echo", "Hello World"])


def command_vulnerable_examples():
    """Exemplos VULNERÁVEIS - DEVEM ser detectados"""
    
    filename = input("Enter filename: ")
    user_command = "ls"
    
    # VULNERÁVEL - f-string
    os.system(f"cat {filename}")
    
    # VULNERÁVEL - concatenação
    subprocess.run("rm -rf " + filename, shell=True)
    
    # VULNERÁVEL - variável direta
    os.system(user_command)
    
    # VULNERÁVEL - Popen com f-string
    subprocess.Popen(f"echo {filename}", shell=True)
    
    # VULNERÁVEL - check_output
    subprocess.check_output(f"grep {filename} data.txt", shell=True)


# ============================================
# CODE INJECTION TESTS
# ============================================

def code_safe_examples():
    """Exemplos SEGUROS - NÃO devem ser detectados"""
    
    # Literal segura - SEGURO
    result = eval("2 + 2")
    
    # Expressão matemática simples - SEGURO
    exec("x = 10")


def code_vulnerable_examples():
    """Exemplos VULNERÁVEIS - DEVEM ser detectados"""
    
    user_code = input("Enter Python code: ")
    formula = "x + y"
    
    # VULNERÁVEL - eval com input
    result = eval(user_code)
    
    # VULNERÁVEL - exec com variável
    exec(formula)
    
    # VULNERÁVEL - eval com f-string
    calc = eval(f"calculate({user_code})")
    
    # VULNERÁVEL - compile
    code_obj = compile(user_code, '<string>', 'eval')
    
    # VULNERÁVEL - __import__
    module_name = user_code
    __import__(module_name)


# ============================================
# CASOS MISTOS
# ============================================

def mixed_vulnerabilities():
    """Múltiplas vulnerabilidades no mesmo ficheiro"""
    
    username = input("Username: ")
    password = input("Password: ")
    
    # SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
    
    # Command Injection
    os.system(f"echo 'Login attempt: {username}'")
    
    # Code Injection
    eval(f"process_user('{username}')")


def attribute_and_subscript_access():
    """Testes de acesso a atributos e subscripts"""
    
    user_data = {"name": "test"}
    config = type('obj', (object,), {'setting': 'value'})()
    
    # VULNERÁVEL - acesso a dicionário
    cursor.execute(user_data["name"])
    
    # VULNERÁVEL - acesso a atributo
    os.system(config.setting)

   