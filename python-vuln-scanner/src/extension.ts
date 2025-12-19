import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { SidebarProvider, Vulnerability } from './SidebarProvider';

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let sidebarProvider: SidebarProvider;
let isScannerEnabled = true;

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("Python Security Scanner");
    outputChannel.appendLine("Extension starting...");
    
    // Set initial context for UI buttons in package.json
    vscode.commands.executeCommand('setContext', 'pythonVulnScanner.enabled', true);

    diagnosticCollection = vscode.languages.createDiagnosticCollection('python-vuln-scanner');
    context.subscriptions.push(diagnosticCollection);

    sidebarProvider = new SidebarProvider();
    vscode.window.registerTreeDataProvider('vuln-scanner-view', sidebarProvider);

    // --- Control Commands ---

    context.subscriptions.push(
        vscode.commands.registerCommand('python-vuln-scanner.openSettings', () => {
            vscode.commands.executeCommand('workbench.action.openSettings', 'pythonVulnScanner');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('python-vuln-scanner.disable', () => {
            isScannerEnabled = false;
            vscode.commands.executeCommand('setContext', 'pythonVulnScanner.enabled', false);
            sidebarProvider.setScannerState(false);
            diagnosticCollection.clear();
            vscode.window.showInformationMessage("Security Scanner: PAUSED");
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('python-vuln-scanner.enable', () => {
            isScannerEnabled = true;
            vscode.commands.executeCommand('setContext', 'pythonVulnScanner.enabled', true);
            sidebarProvider.setScannerState(true);
            
            if (vscode.window.activeTextEditor && vscode.window.activeTextEditor.document.languageId === 'python') {
                runScanner(vscode.window.activeTextEditor.document, context);
            }
            vscode.window.showInformationMessage("Security Scanner: ACTIVE");
        })
    );

    // --- AI Preview & Fix Command ---

    context.subscriptions.push(
        vscode.commands.registerCommand('python-vuln-scanner.requestAiPreview', async (vuln: Vulnerability) => {
            await handleAiFixPreview(vuln, context);
        })
    );

    // --- Workspace Events ---

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            if (document.languageId === 'python' && isScannerEnabled) {
                runScanner(document, context);
            }
        })
    );

    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && editor.document.languageId === 'python' && isScannerEnabled) {
                runScanner(editor.document, context);
            }
        })
    );

    outputChannel.appendLine("Extension loaded successfully.");
}

/**
 * Handles AI suggestion, shows Diff Preview, and asks for confirmation.
 */
async function handleAiFixPreview(vuln: Vulnerability, context: vscode.ExtensionContext) {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    const document = editor.document;
    const line = document.lineAt(vuln.line - 1);
    const indentation = line.text.substring(0, line.firstNonWhitespaceCharacterIndex);

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Generating AI security suggestion...",
        cancellable: false
    }, async () => {
        return new Promise((resolve) => {
            const scriptPath = path.join(context.extensionPath, 'backend', 'scanner.py');
            const command = `python "${scriptPath}" --suggest-fix "${line.text.trim().replace(/"/g, '\\"')}" --vuln-type "${vuln.type}"`;

            cp.exec(command, async (err, stdout) => {
                if (err || !stdout.trim()) {
                    vscode.window.showErrorMessage("AI suggestion failed. Please check if Ollama is running.");
                    return resolve(null);
                }

                const aiSuggestion = indentation + stdout.trim();
                const fullTextWithFix = document.getText().replace(line.text, aiSuggestion);
                const tempUri = vscode.Uri.parse(`untitled:SECURITY_FIX_PREVIEW.py`);

                // Open side-by-side Diff View
                await vscode.commands.executeCommand('vscode.diff', 
                    document.uri, 
                    tempUri, 
                    `Preview Fix: ${vuln.type}`
                );

                // Ask for user confirmation
                const choice = await vscode.window.showInformationMessage(
                    `Apply the suggested AI fix for "${vuln.type}"?`,
                    "Apply Fix", "Cancel"
                );

                if (choice === "Apply Fix") {
                    const edit = new vscode.WorkspaceEdit();
                    edit.replace(document.uri, line.range, aiSuggestion);
                    await vscode.workspace.applyEdit(edit);
                    
                    await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
                    vscode.window.showInformationMessage("Fix applied successfully!");
                }
                resolve(null);
            });
        });
    });
}

/**
 * Orchestrates the Python Static Analysis (AST + Taint).
 */
function runScanner(document: vscode.TextDocument, context: vscode.ExtensionContext) {
    if (!isScannerEnabled) return;

    const scriptPath = path.join(context.extensionPath, 'backend', 'scanner.py');
    const command = `python "${scriptPath}" "${document.fileName}" --json-only`;

    outputChannel.appendLine(`--- Analyzing: ${document.fileName} ---`);

    cp.exec(command, (err, stdout) => {
        if (err || !stdout.trim()) return;

        try {
            const vulnerabilities: Vulnerability[] = JSON.parse(stdout);
            sidebarProvider.refresh(vulnerabilities);
            
            const diagnostics = vulnerabilities.map(v => {
                const range = new vscode.Range(v.line - 1, 0, v.line - 1, 1000);
                const diagnostic = new vscode.Diagnostic(range, `[${v.type}] ${v.description}`, mapSeverity(v.severity));
                diagnostic.source = 'Python Security Scanner';
                diagnostic.code = v.category;
                return diagnostic;
            });
            diagnosticCollection.set(document.uri, diagnostics);
        } catch (e) {
            outputChannel.appendLine(`Scan Error: ${e}`);
        }
    });
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'HIGH': return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM': return vscode.DiagnosticSeverity.Warning;
        default: return vscode.DiagnosticSeverity.Information;
    }
}

export function deactivate() {}