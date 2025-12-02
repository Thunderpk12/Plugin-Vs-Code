import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { SidebarProvider } from './SidebarProvider';

interface Vulnerability {
    line: number;
    column: number;
    type: string;
    function: string;
    pattern: string;
    description: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    confidence: string;
    category: string;
}

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let sidebarProvider: SidebarProvider;

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("Python Vuln Scanner");
    outputChannel.appendLine("Extensão a iniciar...");
    
    vscode.window.showInformationMessage("🚀 O Scanner de Segurança está ATIVO!"); 

    diagnosticCollection = vscode.languages.createDiagnosticCollection('python-vuln-scanner');
    context.subscriptions.push(diagnosticCollection);

    sidebarProvider = new SidebarProvider();
    vscode.window.registerTreeDataProvider('vuln-scanner-view', sidebarProvider);

    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider('python', new SecurityFixProvider(), {
            providedCodeActionKinds: SecurityFixProvider.providedCodeActionKinds
        })
    );

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            if (document.languageId === 'python') {
                runScanner(document, context);
            }
        })
    );

    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && editor.document.languageId === 'python') {
                runScanner(editor.document, context);
            }
        })
    );

    outputChannel.appendLine("Extensão carregada com sucesso.");
}

class SecurityFixProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    provideCodeActions(document: vscode.TextDocument, range: vscode.Range | vscode.Selection, context: vscode.CodeActionContext, token: vscode.CancellationToken): vscode.CodeAction[] {
        return context.diagnostics
            .filter(diagnostic => diagnostic.source === 'Python Security Scanner')
            .map(diagnostic => this.createFix(document, range, diagnostic))
            .filter(action => action !== undefined) as vscode.CodeAction[];
    }

    private createFix(document: vscode.TextDocument, range: vscode.Range, diagnostic: vscode.Diagnostic): vscode.CodeAction | undefined {
        if (diagnostic.message.includes('os.system')) {
            const action = new vscode.CodeAction('Substituir por subprocess.run (Seguro)', vscode.CodeActionKind.QuickFix);
            action.diagnostics = [diagnostic];
            action.isPreferred = true;
            const line = document.lineAt(diagnostic.range.start.line);
            const text = line.text;
            const newText = text.replace('os.system', 'subprocess.run').replace(')', ', shell=False)');
            action.edit = new vscode.WorkspaceEdit();
            action.edit.replace(document.uri, line.range, newText);
            return action;
        }

        if (diagnostic.message.includes('yaml.load')) {
            const action = new vscode.CodeAction('Usar yaml.safe_load', vscode.CodeActionKind.QuickFix);
            action.diagnostics = [diagnostic];
            action.isPreferred = true;
            const line = document.lineAt(diagnostic.range.start.line);
            const newText = line.text.replace('yaml.load', 'yaml.safe_load');
            action.edit = new vscode.WorkspaceEdit();
            action.edit.replace(document.uri, line.range, newText);
            return action;
        }

        if (diagnostic.message.includes('MD5')) {
            const action = new vscode.CodeAction('Atualizar para SHA256', vscode.CodeActionKind.QuickFix);
            action.diagnostics = [diagnostic];
            const line = document.lineAt(diagnostic.range.start.line);
            const newText = line.text.replace('md5', 'sha256');
            action.edit = new vscode.WorkspaceEdit();
            action.edit.replace(document.uri, line.range, newText);
            return action;
        }

        return undefined;
    }
}

function runScanner(document: vscode.TextDocument, context: vscode.ExtensionContext) {
    const scriptPath = path.join(context.extensionPath, 'backend', 'scanner.py');
    const filePath = document.fileName;
    
    outputChannel.appendLine(`--- A analisar: ${filePath} ---`);

    if (!fs.existsSync(scriptPath)) {
        vscode.window.showErrorMessage(`ERRO CRÍTICO: Scanner não encontrado em: ${scriptPath}`);
        outputChannel.appendLine(`ERRO: Ficheiro não existe: ${scriptPath}`);
        return;
    }

    const pythonExecutable = 'python'; 
    const command = `"${pythonExecutable}" "${scriptPath}" "${filePath}" --json-only`;

    cp.exec(command, { cwd: path.join(context.extensionPath, 'backend') }, (err, stdout, stderr) => {
        if (err) {
            outputChannel.appendLine(`ERRO DE EXECUÇÃO: ${err.message}`);
            if (stderr) outputChannel.appendLine(`STDERR: ${stderr}`);
            return;
        }

        try {
            if (!stdout.trim()) {
                outputChannel.appendLine("Aviso: O scanner não retornou dados.");
                return;
            }

            const vulnerabilities: Vulnerability[] = JSON.parse(stdout);
            
            if (sidebarProvider) {
               sidebarProvider.refresh(vulnerabilities);
            }
            
            outputChannel.appendLine(`Sucesso! Encontradas ${vulnerabilities.length} vulnerabilidades.`);

            const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vuln => {
                const lineIndex = vuln.line > 0 ? vuln.line - 1 : 0;
                const range = new vscode.Range(lineIndex, 0, lineIndex, 1000);

                const diagnostic = new vscode.Diagnostic(
                    range,
                    `[${vuln.type}] ${vuln.description}`,
                    mapSeverity(vuln.severity)
                );
                
                diagnostic.source = 'Python Security Scanner';
                diagnostic.code = vuln.category;
                return diagnostic;
            });

            diagnosticCollection.set(document.uri, diagnostics);

        } catch (e) {
            outputChannel.appendLine(`ERRO JSON: Falha ao ler output do Python.`);
            outputChannel.appendLine(`Erro: ${e}`);
            outputChannel.appendLine(`Output recebido: ${stdout}`);
        }
    });
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'HIGH': return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM': return vscode.DiagnosticSeverity.Warning;
        case 'LOW': return vscode.DiagnosticSeverity.Information;
        default: return vscode.DiagnosticSeverity.Hint;
    }
}

export function deactivate() {}