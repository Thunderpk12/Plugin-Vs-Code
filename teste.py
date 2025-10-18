import sqlite3
import os

def vulnerable_queries(user_input, user_id):
    conexao = sqlite3.connect('basedados.db')
    cursor = conexao.cursor()

    # Vulnerabilidade 1: f-string (deve ser detetada)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    
    # Vulnerabilidade 2: Concatenação com '+' (deve ser detetada)
    cursor.execute("SELECT * FROM users WHERE name = '" + user_input + "'")

    # Vulnerabilidade 3: Formatação com '%' (deve ser detetada)
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user_input)

    # Vulnerabilidade 4: Formatação com .format() (deve ser detetada)
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(user_input))

    # CASO SEGURO: f-string sem variáveis (NÃO deve ser detetada)
    cursor.execute(f"SELECT * FROM logs WHERE level = 'ERROR'")

def vulnerable_commands(directory):
    # Vulnerabilidade 5: Command Injection com f-string (deve ser detetada)
    os.system(f"ls -l {directory}")