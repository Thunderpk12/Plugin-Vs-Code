
import sqlite3


def vulneravel(user_id):
    conexao = sqlite3.connect('basedados.db')
    cursor = conexao.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}") 

'''
def seguro(user_id):
    conexao = sqlite3.connect('basedados.db')
    cursor = conexao.cursor() 
    query = "SELECT * FROM utilizadores WHERE id = ?"
    cursor.execute(query, (user_id,))
'''  
   





    
  