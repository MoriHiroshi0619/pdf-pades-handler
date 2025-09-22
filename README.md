# API feita utilizando flask e gunicorn (python)
Descrição: Essa API é capaz de prepaprar e finalizar PDF's no padrão PAdEs para incluir dicionario de assinatura e calcular o byterange do mesmo, além de já prepaprar o conteudo digest para o calculo do hash. 
também é possivel validar a integridade de PAdEs além de comparar dois PAdEs para comparar suas assinaturas

## Para subir em prod

#### Requisitos
- Docker instalado
#### Passos
- clone o projeto via
```bash
  git clone git@github.com:MoriHiroshi0619/pdf-pades-handler.git
```
- copie o env 
```bash
  cp .env.example .env
```
- copie o docker compose 
```bash
  cp docker-compose.yml.example docker-compose.yml
```
- builde o container 
```bash
  docker compose up -d --build
```
- Feito isso a API deverá estar pronta para uso

## Config

#### Porta de funcionamento
Por default a API rodará na porta 8015 configurada no `.env`. 
Se precisar mudar a porta, mude a variavel de ambiente `APP_PORT` no `.env`, depois derrube e levante de novo o container docker `docker compose down & docker compose up -d`



