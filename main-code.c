#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <openssl/sha.h>

// Estrutura para dados do usuário
typedef struct {
    char nome[50];
    char sal[16];
    char hash_senha[129];
} DadosUsuario;

// Funções para gerenciamento de usuários
void gerar_sal(char *sal, int tamanho) {
    const char caracteres[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < tamanho; i++) {
        sal[i] = caracteres[rand() % (sizeof(caracteres) - 1)];
    }
    sal[tamanho] = '\0';
}

void gerar_hash(const char *senha, const char *sal, char *saida_hash) {
    char senha_sal[100];
    snprintf(senha_sal, sizeof(senha_sal), "%s%s", senha, sal);

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char *)senha_sal, strlen(senha_sal), hash);

    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(saida_hash + (i * 2), "%02x", hash[i]);
    }
    saida_hash[128] = '\0';
}

void salvar_usuario(const DadosUsuario *usuario) {
    FILE *arquivo = fopen("usuarios.db", "ab");
    if (arquivo) {
        fwrite(usuario, sizeof(DadosUsuario), 1, arquivo);
        fclose(arquivo);
    } else {
        perror("Erro ao salvar usuário");
    }
}

void registrar_usuario() {
    DadosUsuario usuario;
    char senha[50];

    printf("Digite o nome do usuário: ");
    scanf("%s", usuario.nome);

    printf("Digite a senha: ");
    scanf("%s", senha);

    gerar_sal(usuario.sal, 16);
    gerar_hash(senha, usuario.sal, usuario.hash_senha);

    salvar_usuario(&usuario);
    printf("Usuário cadastrado com sucesso!\n");
}

int validar_usuario() {
    char nome[50], senha[50], hash_verificacao[129];
    printf("Digite o usuário: ");
    scanf("%s", nome);

    printf("Digite a senha: ");
    scanf("%s", senha);

    FILE *arquivo = fopen("usuarios.db", "rb");
    if (!arquivo) {
        printf("Nenhum usuário registrado. Cadastre um novo.\n");
        registrar_usuario();
        return 1;
    }

    DadosUsuario usuario;
    while (fread(&usuario, sizeof(DadosUsuario), 1, arquivo)) {
        if (strcmp(nome, usuario.nome) == 0) {
            gerar_hash(senha, usuario.sal, hash_verificacao);
            if (strcmp(hash_verificacao, usuario.hash_senha) == 0) {
                printf("Login bem-sucedido!\n");
                fclose(arquivo);
                return 1;
            } else {
                printf("Senha incorreta!\n");
                fclose(arquivo);
                return 0;
            }
        }
    }

    printf("Usuário não encontrado.\n");
    fclose(arquivo);
    return 0;
}

// Funções para execução de comandos
void executar_processo(const char *comando) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("Erro ao criar processo");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        printf("Processo criado (PID: %d) executando: %s\n", getpid(), comando);
        execlp(comando, comando, NULL);
        perror("Erro ao executar comando");
        exit(EXIT_FAILURE);
    } else {
        wait(NULL); // Processo pai espera o filho terminar
    }
}

// Shell principal
void iniciar_shell() {
    char entrada[100];

    while (1) {
        printf("MiniSO> ");
        fgets(entrada, sizeof(entrada), stdin);
        entrada[strcspn(entrada, "\n")] = '\0'; // Remove o '\n'

        if (strcmp(entrada, "sair") == 0) {
            printf("Encerrando MiniSO.\n");
            break;
        } else if (strncmp(entrada, "listar", 6) == 0) {
            executar_processo("ls");
        } else if (strncmp(entrada, "criar arquivo", 13) == 0) {
            char nome_arquivo[50];
            sscanf(entrada, "criar arquivo %s", nome_arquivo);
            FILE *arquivo = fopen(nome_arquivo, "w");
            if (arquivo) {
                fprintf(arquivo, "Conteúdo gerado automaticamente.\n");
                fclose(arquivo);
                printf("Arquivo '%s' criado com sucesso.\n", nome_arquivo);
            } else {
                perror("Erro ao criar arquivo");
            }
        } else if (strncmp(entrada, "apagar arquivo", 14) == 0) {
            char nome_arquivo[50];
            sscanf(entrada, "apagar arquivo %s", nome_arquivo);
            if (remove(nome_arquivo) == 0) {
                printf("Arquivo '%s' apagado com sucesso.\n", nome_arquivo);
            } else {
                perror("Erro ao apagar arquivo");
            }
        } else if (strncmp(entrada, "criar diretorio", 15) == 0) {
            char nome_diretorio[50];
            sscanf(entrada, "criar diretorio %s", nome_diretorio);
            if (mkdir(nome_diretorio, 0777) == 0) {
                printf("Diretório '%s' criado com sucesso.\n", nome_diretorio);
            } else {
                perror("Erro ao criar diretório");
            }
        } else if (strncmp(entrada, "apagar diretorio", 16) == 0) {
            char nome_diretorio[50];
            sscanf(entrada, "apagar diretorio %s", nome_diretorio);
            if (rmdir(nome_diretorio) == 0) {
                printf("Diretório '%s' apagado com sucesso.\n", nome_diretorio);
            } else {
                perror("Erro ao apagar diretório");
            }
        } else {
            printf("Comando não reconhecido: %s\n", entrada);
        }
    }
}

// Função principal
int main() {
    srand(time(NULL));

    printf("Bem-vindo ao MiniSO!\n");
    if (!validar_usuario()) {
        return EXIT_FAILURE;
    }

    iniciar_shell();
    return EXIT_SUCCESS;
}
