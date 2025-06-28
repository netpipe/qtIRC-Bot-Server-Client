// Threaded IRC Server with Enhancements
// Qt 5.12, single-file version under 1000 lines

#include <QtWidgets>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSslSocket>
#include <QSslCertificate>
#include <QSslKey>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QReadWriteLock>
#include <QSet>
#include <QMap>
#include <QThread>

class Channel : public QObject {
    Q_OBJECT
public:
    QString name;
    QString topic;
    QSet<QString> users;
    QSet<QString> ops;

    explicit Channel(const QString &name, QObject* parent = nullptr)
        : QObject(parent), name(name) {}

    void join(const QString &user) { users.insert(user); }
    void part(const QString &user) { users.remove(user); ops.remove(user); }
    QStringList userList() const { return users.values(); }
    bool hasUser(const QString &user) const { return users.contains(user); }
    void setTopic(const QString &t) { topic = t; }
    bool isOp(const QString& user) const { return ops.contains(user); }
    void opUser(const QString& user) { if (users.contains(user)) ops.insert(user); }
    void deopUser(const QString& user) { ops.remove(user); }
};

QMap<QString, Channel*> channels;
QReadWriteLock channelsLock;
QMap<QString, QTcpSocket*> nickToSocket;
QMap<QString, QString> userPasswords; // for in-memory auth fallback
QSet<QString> bannedIPs;
QReadWriteLock nickLock;

bool isBanned(const QString& ip) {
    QReadLocker lock(&nickLock);
    return bannedIPs.contains(ip);
}

class ClientHandler : public QThread {
    Q_OBJECT
public:
    QTcpSocket* socket;
    QString nickname;
    QString currentChannel;
    QTextEdit* log;
    QString ip;
    bool identified = false;

    ClientHandler(QTcpSocket* sock, QTextEdit* logger) : socket(sock), log(logger) {
        ip = socket->peerAddress().toString();
    }

    void run() override {
        if (isBanned(ip)) {
            socket->write(":server 465 * :You are banned\r\n");
            socket->disconnectFromHost();
            return;
        }
        connect(socket, &QTcpSocket::readyRead, this, &ClientHandler::handleInput, Qt::DirectConnection);
        connect(socket, &QTcpSocket::disconnected, this, &ClientHandler::cleanup);
        exec();
    }

    void handleInput() {
        while (socket->canReadLine()) {
            QString line = QString::fromUtf8(socket->readLine()).trimmed();
            log->append("[" + nickname + "] " + line);
            processCommand(line);
        }
    }

    void processCommand(const QString& line) {
        if (line.startsWith("PING")) {
            send("PONG :server");
            return;
        }
        if (line.startsWith("NICK ")) {
            nickname = line.section(' ', 1);
            QWriteLocker locker(&nickLock);
            nickToSocket[nickname] = socket;
            send("001 " + nickname + " :Welcome!");
        } else if (line.startsWith("JOIN ")) {
        QString chan = line.section(' ', 1).trimmed();
        if (!chan.startsWith('#')) return;

        Channel* ch;
        {
            QWriteLocker locker(&channelsLock);
            if (!channels.contains(chan))
                channels[chan] = new Channel(chan);
            ch = channels[chan];
            ch->join(nickname);  // ✅ Join FIRST
        }

        currentChannel = chan;

        // Send JOIN to self
        send(":" + nickname + " JOIN " + chan);

        // Send topic
        send("332 " + nickname + " " + chan + " :" + (ch->topic.isEmpty() ? "No topic" : ch->topic));

        // Build NAMES list, including self
        QStringList names;
        {
           //  names << nickname;
            QReadLocker locker(&channelsLock);
            for (const QString& user : ch->userList()) {
             //   QString prefix = ch->isOp(user) ? "@" : "";
             //   names << prefix + user;
                names << user;
            }
        }
        send("353 " + nickname + " = " + chan + " :" + names.join(" "));
        send("366 " + nickname + " " + chan + " :End of NAMES list");

        // Broadcast JOIN to others
        broadcast(chan, ":" + nickname + " JOIN " + chan, true);
    }
else if (line.startsWith("NAMES ")) {
            QString chan = line.section(' ', 1).trimmed();
        //    QReadLocker locker(&channelsLock);
            QStringList names;
            {
                QReadLocker locker(&channelsLock);
                for (const QString& user : channels[chan]->userList()) {
                    QString prefix;
                   //if (channels[chan]->ops.contains(user)) prefix = "@";
                  //  names << prefix + user;
                     names << user;
                }
            }
            send("353 " + nickname + " = " + chan + " :" + names.join(" "));
            send("366 " + nickname + " " + chan + " :End of NAMES list");
        } else if (line.startsWith("PART ")) {
            QString chan = line.section(' ', 1).trimmed();
            QReadLocker locker(&channelsLock);
            if (channels.contains(chan)) {
                channels[chan]->part(nickname);
                send(":" + nickname + " PART " + chan);
                broadcast(chan, ":" + nickname + " PART " + chan, true);
            }
        } else if (line.startsWith("PRIVMSG ")) {
            QString target = line.section(' ', 1, 1);
            QString msg = line.section(' ', 2);
            if (target.startsWith('#')) {
                broadcast(target, ":" + nickname + " PRIVMSG " + target + " " + msg, true);
            } else {
                QReadLocker locker(&nickLock);
                if (nickToSocket.contains(target)) {
                    nickToSocket[target]->write((":" + nickname + " PRIVMSG " + target + " :" + msg + "\r\n").toUtf8());
                }
            }
        } else if (line.startsWith("/msg ")) {
            QString target = line.section(' ', 1, 1);
            QString msg = line.section(' ', 2);
            QReadLocker locker(&nickLock);
            if (nickToSocket.contains(target)) {
                nickToSocket[target]->write((":" + nickname + " PRIVMSG " + target + " :" + msg + "\r\n").toUtf8());
            }
        } else if (line.startsWith("/whois ")) {
            QString target = line.section(' ', 1).trimmed();
            QReadLocker locker(&nickLock);
            send(nickToSocket.contains(target) ? "311 " + nickname + " " + target + " :User info here" : "401 " + nickname + " " + target + " :No such nick");
        } else if (line.startsWith("/register ")) {
            QStringList parts = line.split(' ');
            if (parts.size() >= 3) {
                QSqlQuery q;
                q.prepare("INSERT INTO users (nick, password) VALUES (?, ?)");
                q.addBindValue(parts[1]);
                q.addBindValue(parts[2]);
                q.exec();
                send(":server NOTICE " + nickname + " :Registered");
            }
        } else if (line.startsWith("/identify ")) {
            QStringList parts = line.split(' ');
            if (parts.size() >= 3) {
                QSqlQuery q("SELECT password FROM users WHERE nick='" + parts[1] + "'");
                if (q.next() && q.value(0).toString() == parts[2]) {
                    identified = true;
                    send(":server NOTICE " + nickname + " :Identified");
                } else send("464 " + nickname + " :Password incorrect");
            }
        } else if (line.startsWith("/op ")) {
            if (!currentChannel.isEmpty()) {
                QWriteLocker locker(&channelsLock);
                Channel* ch = channels[currentChannel];
                if (ch->isOp(nickname)) {
                    QString target = line.section(' ', 1);
                    ch->opUser(target);
                    send(":server NOTICE " + nickname + " :" + target + " is now op");
                }
            }
        } else if (line.startsWith("/kick ")) {
            QString target = line.section(' ', 1);
            if (!currentChannel.isEmpty()) {
                QWriteLocker locker(&channelsLock);
                Channel* ch = channels[currentChannel];
                if (ch->isOp(nickname)) {
                    ch->part(target);
                    broadcast(currentChannel, ":" + nickname + " KICK " + currentChannel + " " + target);
                }
            }
        } else if (line.startsWith("/topic ")) {
            QString topic = line.section(' ', 1);
            if (!currentChannel.isEmpty()) {
                QWriteLocker locker(&channelsLock);
                Channel* ch = channels[currentChannel];
                if (ch->isOp(nickname)) {
                    ch->setTopic(topic);
                    broadcast(currentChannel, ":" + nickname + " TOPIC " + currentChannel + " :" + topic);
                }
            }
        } else if (line.startsWith("QUIT")) {
            cleanup();
        } else {
            send("421 " + nickname + " :Unknown command");
        }
    }

    void send(const QString& msg) {
        socket->write((msg + "\r\n").toUtf8());
    }

    void broadcast(const QString& channel, const QString& message, bool skipSelf = false) {
        QReadLocker locker(&channelsLock);
        if (!channels.contains(channel)) return;
        for (const QString& user : channels[channel]->users) {
            QReadLocker lock2(&nickLock);
            if (user == nickname && skipSelf) continue;
            if (nickToSocket.contains(user)) {
                nickToSocket[user]->write((message + "\r\n").toUtf8());
            }
        }
    }

    void cleanup() {
        log->append("[" + nickname + "] disconnected.");
        {
            QWriteLocker locker(&nickLock);
            nickToSocket.remove(nickname);
        }
        {
            QWriteLocker locker(&channelsLock);
            if (!currentChannel.isEmpty() && channels.contains(currentChannel)) {
                channels[currentChannel]->part(nickname);
                broadcast(currentChannel, ":" + nickname + " QUIT :Disconnected", true);
            }
        }
        socket->deleteLater();
        quit();
    }
};

class IrcServer : public QWidget {
    Q_OBJECT
public:
    IrcServer(QWidget* parent = nullptr) : QWidget(parent) {
        setWindowTitle("Threaded IRC Server");
        resize(700, 400);
        log = new QTextEdit(this);
        log->setReadOnly(true);
        QVBoxLayout* layout = new QVBoxLayout(this);
        layout->addWidget(log);
        setLayout(layout);

        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName("irc.db");
        db.open();
        QSqlQuery q("CREATE TABLE IF NOT EXISTS users (nick TEXT PRIMARY KEY, password TEXT)");

        connect(&plainServer, &QTcpServer::newConnection, this, &IrcServer::handlePlain);
        connect(&sslServer, &QTcpServer::newConnection, this, &IrcServer::handleSSL);

        if (!plainServer.listen(QHostAddress::Any, 6667)) log->append("❌ Failed to start plain server.");
        else log->append("✅ Plain IRC listening on 6667");

        if (!sslServer.listen(QHostAddress::Any, 6697)) log->append("❌ Failed to start SSL server.");
        else log->append("✅ SSL IRC listening on 6697");

        loadSSL();
    }

private:
    QTcpServer plainServer, sslServer;
    QSslCertificate cert;
    QSslKey key;
    QTextEdit* log;

    void loadSSL() {
        QFile certFile("cert.pem"), keyFile("key.pem");
        certFile.open(QIODevice::ReadOnly);
        keyFile.open(QIODevice::ReadOnly);
        cert = QSslCertificate(certFile.readAll(), QSsl::Pem);
        key = QSslKey(keyFile.readAll(), QSsl::Rsa, QSsl::Pem);
    }

    void handlePlain() {
        QTcpSocket* sock = plainServer.nextPendingConnection();
        startClient(sock);
    }

    void handleSSL() {
        QSslSocket* sock = qobject_cast<QSslSocket*>(sslServer.nextPendingConnection());
        sock->setLocalCertificate(cert);
        sock->setPrivateKey(key);
        sock->startServerEncryption();
        startClient(sock);
    }

    void startClient(QTcpSocket* sock) {
        auto* handler = new ClientHandler(sock, log);
        handler->start();
    }
};

#include "main.moc"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    IrcServer server;
    server.show();
    return app.exec();
}
