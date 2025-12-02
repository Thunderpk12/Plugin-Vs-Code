import * as vscode from 'vscode';


export interface Vulnerability {
    line: number;
    column: number;
    type: string;
    description: string;
    severity: string;
    category: string;
}

export class SidebarProvider implements vscode.TreeDataProvider<VulnItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<VulnItem | undefined | null | void> = new vscode.EventEmitter<VulnItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<VulnItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private vulnerabilities: Vulnerability[] = [];

    refresh(vulns: Vulnerability[]): void {
        this.vulnerabilities = vulns;
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: VulnItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: VulnItem): Thenable<VulnItem[]> {
        if (!element) {
            // NÍVEL 1: CATEGORIAS (Raiz)
            const categories = Array.from(new Set(this.vulnerabilities.map(v => v.category))).sort();
            
            if (categories.length === 0) {
                return Promise.resolve([new VulnItem("Nenhuma vulnerabilidade", "vazio", vscode.TreeItemCollapsibleState.None)]);
            }

            return Promise.resolve(categories.map(cat => {
                const count = this.vulnerabilities.filter(v => v.category === cat).length;
                // O segundo argumento "categoria" é fundamental para o passo seguinte
                return new VulnItem(`${cat} (${count})`, "categoria", vscode.TreeItemCollapsibleState.Expanded);
            }));
        } else {
            // NÍVEL 2: ITENS (Dentro da categoria)
            // Se o item pai for do tipo "categoria", procuramos os filhos
            if (element.contextValue === "categoria") {
                const categoryCode = element.label.split(' ')[0]; // Pega o "A03" do texto "A03 (5)"
                const filtered = this.vulnerabilities.filter(v => v.category === categoryCode);
                
                return Promise.resolve(filtered.map(v => {
                    return new VulnItem(
                        `Linha ${v.line}: ${v.type}`, // Título do erro
                        "item", // Tipo
                        vscode.TreeItemCollapsibleState.None,
                        { // Comando ao clicar (abrir ficheiro na linha certa)
                            command: 'vscode.open',
                            title: 'Abrir Ficheiro',
                            arguments: [vscode.window.activeTextEditor?.document.uri, { selection: new vscode.Range(v.line - 1, 0, v.line - 1, 0) }]
                        },
                        v.severity,
                        v.description // Tooltip
                    );
                }));
            }
        }
        return Promise.resolve([]);
    }
}

class VulnItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        private type: string, // "categoria" ou "item"
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly command?: vscode.Command,
        public readonly severity?: string,
        public readonly descText?: string
    ) {
        super(label, collapsibleState);
        
        
        this.contextValue = type; 
        
      
        if (descText) {
            this.tooltip = new vscode.MarkdownString(`**${label}**\n\n${descText}`);
            this.description = ""; 
        } else {
            this.tooltip = label;
        }
        
      
        if (severity === 'HIGH') {
            this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('testing.iconFailed')); // Vermelho
        } else if (severity === 'MEDIUM') {
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconQueued')); // Amarelo
        } else if (type === "categoria") {
            this.iconPath = new vscode.ThemeIcon('folder-opened'); // Pasta
        } else {
            this.iconPath = new vscode.ThemeIcon('info');
        }
    }
}