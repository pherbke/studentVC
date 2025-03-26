from src import create_app, socketio
import os

if os.path.exists("instance/database.db"):
    os.remove("instance/database.db")


app = create_app()
app.config['DEBUG'] = True
app.config['SERVER_URL'] = "https://127.0.0.1:8080"

cert = "./instance/fullchain.pem"
key = "./instance/privkey.pem"

if __name__ == '__main__':
    if os.path.exists(cert) and os.path.exists(key):
        socketio.run(app, debug=True, port=8080,
                     ssl_context=(cert, key), host='0.0.0.0', allow_unsafe_werkzeug=True)
    else:
        socketio.run(app, debug=True, port=8080,
                     ssl_context='adhoc', host='0.0.0.0', allow_unsafe_werkzeug=True)
