// File: SimpleIrcServer.cpp
#include <QtWidgets>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSslSocket>
#include <QSslKey>
#include <QSslCertificate>

struct Client {
    QTcpSocket* socket;
    QString nickname;
    QString channel;
};

class IrcServer : public QWidget {
    Q_OBJECT
public:
    IrcServer(QWidget* parent = nullptr) : QWidget(parent) {
        setWindowTitle("Simple IRC Server");
        resize(600, 400);
        log = new QTextEdit(this);
        log->setReadOnly(true);
        QVBoxLayout* layout = new QVBoxLayout(this);
        layout->addWidget(log);
        setLayout(layout);

        connect(&server, &QTcpServer::newConnection, this, &IrcServer::handleNewConnection);
        connect(&sslServer, &QTcpServer::newConnection, this, &IrcServer::handleNewSslConnection);

        if (!server.listen(QHostAddress::Any, 6667)) {
            log->append("Error starting plain server.");
        } else {
            log->append("Plain IRC server running on port 6667.");
        }

        if (!sslServer.listen(QHostAddress::Any, 6697)) {
            log->append("Error starting SSL server.");
        } else {
            log->append("SSL IRC server running on port 6697.");
        }

        loadSslCertificate();
    }

private:
    QTcpServer server, sslServer;
    QTextEdit* log;
    QList<Client*> clients;
    QSslCertificate cert;
    QSslKey key;

    void loadSslCertificate() {
        QFile certFile("cert.pem"), keyFile("key.pem");
        certFile.open(QIODevice::ReadOnly);
        keyFile.open(QIODevice::ReadOnly);
        cert = QSslCertificate(certFile.readAll(), QSsl::Pem);
        key = QSslKey(keyFile.readAll(), QSsl::Rsa, QSsl::Pem);
    }

    void handleNewConnection() {
        QTcpSocket* socket = server.nextPendingConnection();
        setupSocket(socket, false);
    }

    void handleNewSslConnection() {
        QSslSocket* sslSocket = qobject_cast<QSslSocket*>(sslServer.nextPendingConnection());
        sslSocket->setLocalCertificate(cert);
        sslSocket->setPrivateKey(key);
        sslSocket->startServerEncryption();
        setupSocket(sslSocket, true);
    }

    void setupSocket(QTcpSocket* socket, bool isSsl) {
        Client* client = new Client{ socket, "", "" };
        clients.append(client);
        log->append("New client connected.");

        connect(socket, &QTcpSocket::readyRead, [this, client]() {
            while (client->socket->canReadLine()) {
                QString line = QString::fromUtf8(client->socket->readLine()).trimmed();
                log->append("Received: " + line);
                processCommand(client, line);
            }
        });

        connect(socket, &QTcpSocket::disconnected, [this, client]() {
            log->append("Client disconnected: " + client->nickname);
            clients.removeAll(client);
            delete client->socket;
            delete client;
        });
    }

    void processCommand(Client* sender, const QString& line) {
        if (line.startsWith("NICK ")) {
            sender->nickname = line.section(' ', 1);
            sendToClient(sender, ":server 001 " + sender->nickname + " :Welcome!");
        } else if (line.startsWith("JOIN ")) {
            QString channel = line.section(' ', 1).trimmed();
            if (!channel.startsWith('#')) {
                sendToClient(sender, "403 " + sender->nickname + " " + channel + " :No such channel");
                return;
            }
            sender->channel = channel;

            // Acknowledge to the sender
            sendToClient(sender, ":" + sender->nickname + " JOIN " + channel);
            sendToClient(sender, ":server 332 " + sender->nickname + " " + channel + " :Welcome to " + channel);
            sendToClient(sender, ":server 353 " + sender->nickname + " = " + channel + " :" + sender->nickname);
            sendToClient(sender, ":server 366 " + sender->nickname + " " + channel + " :End of /NAMES list.");

            // Notify others
            broadcast(channel, ":" + sender->nickname + " JOIN " + channel, sender);
        }
else if (line.startsWith("PRIVMSG ")) {
            QString rest = line.section(' ', 1);
            QString target = rest.section(' ', 0, 0);
            QString message = rest.section(' ', 1);
            if (target.startsWith('#')) {
                broadcast(target, ":" + sender->nickname + " PRIVMSG " + target + " " + message, sender);
            } else {
                sendToNickname(target, ":" + sender->nickname + " PRIVMSG " + target + " " + message);
            }
        } else if (line.startsWith("/msg ") || line.startsWith("/private ")) {
            QString rest = line.section(' ', 1);
            QString target = rest.section(' ', 0, 0);
            QString message = rest.section(' ', 1);
            sendToNickname(target, ":" + sender->nickname + " PRIVMSG " + target + " :" + message);
        } else {
            sendToClient(sender, "Unknown command.");
        }
    }

    void sendToClient(Client* client, const QString& message) {
        client->socket->write((message + "\r\n").toUtf8());
    }

    void broadcast(const QString& channel, const QString& message, Client* exclude = nullptr) {
        for (Client* c : clients) {
            if (c != exclude && c->channel == channel) {
                sendToClient(c, message);
            }
        }
    }

    void sendToNickname(const QString& nick, const QString& message) {
        for (Client* c : clients) {
            if (c->nickname == nick) {
                sendToClient(c, message);
                return;
            }
        }
    }
};


int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    IrcServer server;
    server.show();
    return app.exec();
}
#include "main.moc"
