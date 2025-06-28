// IrcServer.cpp - Single-file IRC Server with SSL, user/channel handling, and basic GUI log window
// Qt 5.12+, use with: QT += core network sql widgets

#include <QtCore>
#include <QtNetwork>
#include <QtSql>
#include <QtWidgets>

class Logger : public QTextEdit {
public:
    Logger() {
        setReadOnly(true);
        resize(800, 400);
        setWindowTitle("QtIRC Server Log");
        show();
    }
    void log(const QString &msg) {
        append(QTime::currentTime().toString("hh:mm:ss ") + msg);
    }
};

Logger *logger;

class IrcClientHandler : public QObject {
    Q_OBJECT
public:
    IrcClientHandler(QTcpSocket *socket, QObject *parent = nullptr)
        : QObject(parent), socket(socket), user("*"), registered(false), identified(false) {
        connect(socket, &QTcpSocket::readyRead, this, &IrcClientHandler::read);
        connect(socket, &QTcpSocket::disconnected, this, &IrcClientHandler::disconnected);
        send("NOTICE * :Welcome to QtIRC. Please /register or /identify.");
    }

    void send(const QString &msg) {
        socket->write((msg + "\r\n").toUtf8());
    }

    QString getUser() const { return user; }

signals:
    void finished(IrcClientHandler*);

private slots:
    void read() {
        while (socket->canReadLine()) {
            QString line = QString::fromUtf8(socket->readLine()).trimmed();
            logger->log(user + " > " + line);

            if (line.startsWith("PING")) {
                send("PONG :pong");
                continue;
            }
            QStringList parts = line.split(' ');
            if (parts.isEmpty()) continue;

            QString cmd = parts[0].toUpper();
            if (cmd == "/REGISTER" && parts.size() >= 3) {
                QString u = parts[1], p = parts[2];
                QSqlQuery q;
                q.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
                q.addBindValue(u);
                q.addBindValue(p);
                if (q.exec()) {
                    send(":server 001 " + u + " :Registered.");
                } else {
                    send(":server 433 * " + u + " :Username taken.");
                }
            } else if (cmd == "/IDENTIFY" && parts.size() >= 3) {
                QString u = parts[1], p = parts[2];
                QSqlQuery q;
                q.prepare("SELECT * FROM users WHERE username=? AND password=?");
                q.addBindValue(u);
                q.addBindValue(p);
                q.exec();
                if (q.next()) {
                    identified = true;
                    user = u;
                    handlers[user] = this;
                    send(":server 001 " + user + " :Welcome to QtIRC!");
                } else {
                    send(":server 464 * :Login failed.");
                }
            } else if (cmd == "/WHOIS" && parts.size() >= 2) {
                QString target = parts[1];
                if (handlers.contains(target)) {
                    send(":server 311 " + user + " " + target + " ~ident 127.0.0.1 * :QtIRC User");
                    send(":server 318 " + user + " " + target + " :End of WHOIS");
                } else {
                    send(":server 401 " + user + " " + target + " :No such nick");
                }
            } else if (cmd == "/MSG" && parts.size() >= 3) {
                QString target = parts[1];
                QString message = line.section(' ', 2);
                if (handlers.contains(target)) {
                    handlers[target]->send(":" + user + " PRIVMSG " + target + " :" + message);
                    send(":" + user + " PRIVMSG " + target + " :" + message);
                } else {
                    send(":server 401 " + user + " " + target + " :User not found");
                }
            } else if (cmd == "/JOIN" && parts.size() >= 2) {
                QString chan = parts[1];
                channels[chan].insert(user);
                send(":" + user + " JOIN " + chan);
                foreach (const QString &u, channels[chan]) {
                    if (u != user && handlers.contains(u))
                        handlers[u]->send(":" + user + " JOIN " + chan);
                }
            } else if (cmd == "/PART" && parts.size() >= 2) {
                QString chan = parts[1];
                channels[chan].remove(user);
                send(":" + user + " PART " + chan);
            } else if (cmd == "/TOPIC" && parts.size() >= 3) {
                QString chan = parts[1];
                QString topic = line.section(' ', 2);
                channelTopics[chan] = topic;
                foreach (const QString &u, channels[chan])
                    if (handlers.contains(u))
                        handlers[u]->send(":server 332 " + u + " " + chan + " :" + topic);
            } else if (cmd == "/REGISTERCHAN" && parts.size() >= 2) {
                QString chan = parts[1];
                QSqlQuery q;
                q.prepare("INSERT INTO channels (name, owner) VALUES (?, ?)");
                q.addBindValue(chan);
                q.addBindValue(user);
                if (q.exec())
                    send(":server NOTICE " + user + " :Channel " + chan + " registered.");
                else
                    send(":server NOTICE " + user + " :Channel already exists.");
            } else {
                send(":server 421 * " + cmd + " :Unknown command");
            }
        }
    }

    void disconnected() {
        handlers.remove(user);
        for (auto it = channels.begin(); it != channels.end(); ++it) {
            it.value().remove(user);
        }
        emit finished(this);
        socket->deleteLater();
    }

private:
    QTcpSocket *socket;
    QString user;
    bool registered;
    bool identified;
    static inline QMap<QString, IrcClientHandler*> handlers;
    static inline QMap<QString, QSet<QString>> channels;
    static inline QMap<QString, QString> channelTopics;
};

class IrcServer : public QTcpServer {
    Q_OBJECT
public:
    IrcServer(bool sslMode, quint16 port, QObject *parent = nullptr)
        : QTcpServer(parent), sslMode(sslMode) {
        listen(QHostAddress::Any, port);
        logger->log((sslMode ? "[SSL]" : "[PLAIN]") + QString(" IRC Server listening on port %1").arg(port));
    }

protected:
    void incomingConnection(qintptr socketDescriptor) override {
        QTcpSocket *socket;
        if (sslMode) {
            QSslSocket *sslSocket = new QSslSocket();
            sslSocket->setSocketDescriptor(socketDescriptor);
            sslSocket->setLocalCertificate("server.crt");
            sslSocket->setPrivateKey("server.key");
            sslSocket->startServerEncryption();
            socket = sslSocket;
        } else {
            socket = new QTcpSocket();
            socket->setSocketDescriptor(socketDescriptor);
        }

        QThread *thread = new QThread;
        IrcClientHandler *handler = new IrcClientHandler(socket);
        handler->moveToThread(thread);

        connect(thread, &QThread::started, [handler]() {
            // Ready to start handling
        });
        connect(handler, &IrcClientHandler::finished, thread, &QThread::quit);
        connect(thread, &QThread::finished, handler, &QObject::deleteLater);
        connect(thread, &QThread::finished, thread, &QObject::deleteLater);

        thread->start();
    }


private:
    bool sslMode;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    logger = new Logger();

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("ircusers.db");
    if (!db.open()) {
        qCritical() << "Failed to open database.";
        return 1;
    }
    QSqlQuery q;
    q.exec("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)");
    q.exec("CREATE TABLE IF NOT EXISTS channels (name TEXT PRIMARY KEY, owner TEXT)");

    new IrcServer(false, 6667);
    new IrcServer(true, 6697);

    return app.exec();
}

#include "main.moc"
