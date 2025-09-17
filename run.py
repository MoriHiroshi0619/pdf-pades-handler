# run.py
from app import create_app

app = create_app()

if __name__ == "__main__":
    # ambiente de desenvolvimento; NÃO usar em produção
    app.run(host="0.0.0.0", port=5000, debug=True)
