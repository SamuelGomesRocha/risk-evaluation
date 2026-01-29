import os
import secrets
from typing import Annotated
from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from dotenv import load_dotenv

# 1. Carrega variáveis de ambiente
load_dotenv()

app = FastAPI(
    title="API de Análise de Riscos - TJGO",
    description="Endpoint seguro para recepção de documentos (DOD, ETP, TR).",
    version="0.2.0"
)

security = HTTPBasic()

# 2. Função de Segurança (Autenticação)
def verificar_credenciais(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    """
    Verifica se o usuário e senha enviados no header correspondem ao .env.
    Usa secrets.compare_digest para evitar ataques de timing.
    """
    # Pega do .env ou usa padrão inseguro se não achar (apenas para teste)
    usuario_correto = os.getenv("API_USERNAME", "admin")
    senha_correta = os.getenv("API_PASSWORD", "admin")

    # Compara bytes para segurança criptográfica
    is_user_ok = secrets.compare_digest(credentials.username.encode("utf8"), usuario_correto.encode("utf8"))
    is_pass_ok = secrets.compare_digest(credentials.password.encode("utf8"), senha_correta.encode("utf8"))

    if not (is_user_ok and is_pass_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais de acesso inválidas.",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# 3. Validação de Arquivos
TIPOS_PERMITIDOS = ["application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"]

def validar_extensao(file: UploadFile, label: str):
    if file.content_type not in TIPOS_PERMITIDOS:
        raise HTTPException(
            status_code=415,
            detail=f"O arquivo {label} ({file.filename}) deve ser PDF ou DOCX."
        )

# 4. O Endpoint Principal
@app.post("/api/v1/docs-principais")
async def recepcionar_arquivos(
    # Injeção de dependência: O código só roda se 'verificar_credenciais' passar
    usuario: Annotated[str, Depends(verificar_credenciais)], 
    dod: UploadFile = File(..., description="Documento de Oficialização da Demanda"),
    etp: UploadFile = File(..., description="Estudo Técnico Preliminar"),
    tr: UploadFile = File(..., description="Termo de Referência")
):
    """
    Recebe DOD, ETP e TR. Requer autenticação Basic Auth.
    """
    
    # Validações
    validar_extensao(dod, "DOD")
    validar_extensao(etp, "ETP")
    validar_extensao(tr, "TR")

    # Leitura (Simulação de ingestão)
    # Aqui os binários estão prontos para serem enviados para o extrator de texto
    bytes_dod = await dod.read()
    bytes_etp = await etp.read()
    bytes_tr = await tr.read()

    return {
        "status": "sucesso",
        "usuario_responsavel": usuario,
        "mensagem": "Arquivos recepcionados com segurança.",
        "dados_recebidos": {
            "dod": {"nome": dod.filename, "tamanho": len(bytes_dod)},
            "etp": {"nome": etp.filename, "tamanho": len(bytes_etp)},
            "tr":  {"nome": tr.filename, "tamanho": len(bytes_tr)}
        }
    }