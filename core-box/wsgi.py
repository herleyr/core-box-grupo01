from app import create_app

app = create_app()

if __name__ == "__main__":
    # Apenas desenvolvimento local; produção usa gunicorn (ver Dockerfile)
    app.run(host="0.0.0.0", port=8000)
