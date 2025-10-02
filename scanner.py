import ast 

def read_code(file_path):
    """
    En:Opens a file reads its content and returns as AST
    Pt:Abre um ficheiro le o seu conteudo e  devolve como AST
    
    """
    with open(file_path, 'r',encoding='utf-8') as file:
        code = file.read()
        code_ast = ast.parse(code)
    return code_ast

def get_function_name(node):
    """
    En:Gets the name of the function being called
    Pt:Obtém o nome da função que está a ser chamada
    
    Ex:  "cursor.execute()" returns "execute"
    """
    if hasattr(node.func, 'attr'):    # Ex: pessoa.idade -> retorna idade
        return node.func.attr
    
    if hasattr(node.func, 'id'):      # Ex: print() -> retorna print
        return node.func.id
    
    return ""


def has_fstring(node):
    """
    Pt:Verifica se a função está a usar f-string nos argumentos
    En:Checks if the function is using f-string in arguments
    
    """
    if not node.args:       # Verificar se tem argumentos
        return False
    
    first_arg = node.args[0]
                                                 
    if isinstance(first_arg, ast.JoinedStr):  # JoinedStr = f-string no AST
        return True
    
    return False


def code_analysis(code_ast):
    """Analisa o AST e devolve informacao sobre funcoes e classes"""
    problems = []

    for code in ast.walk(code_ast):
        if isinstance(code, ast.Call):
            function_name = get_function_name(code)
            if function_name in ['execute', 'executemany', 'query']:
                if has_fstring(code):
                    problems.append({
                        'line': code.lineno,
                        'type': 'SQL Injection',
                        'description': 'Uso de f-string ',
                    })
    return problems
 
def mostrar_resultados(problems):
    """
    Print para teste
    """
    if len(problems) == 0:
        print(" Nenhum problema encontrado! Código parece seguro.")
        return
    
    for i, problema in enumerate(problems, 1):
        print(f"\nProblema #{i}")
        print(f"   Linha: {problema['line']}")
        print(f"    Tipo: {problema['type']}")
        print(f"   Descrição: {problema['description']}")
    
if __name__ == "__main__":
    file_path = "teste.py"
    codigo = read_code(file_path)   
    resultado = code_analysis(codigo)    
    mostrar_resultados(resultado)
        
   