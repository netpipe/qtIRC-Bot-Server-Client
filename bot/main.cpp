#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QLineEdit>
#include <QSslSocket>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QRandomGenerator>
#include <QTimer>
#include <QSqlQuery>

class IRCBot : public QWidget {
    Q_OBJECT

public:
    IRCBot(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("Qt IRC Bot");
        resize(600, 400);

        QVBoxLayout *layout = new QVBoxLayout(this);
        chatDisplay = new QTextEdit(this);
        chatDisplay->setReadOnly(true);
        inputBox = new QLineEdit(this);

        layout->addWidget(chatDisplay);
        layout->addWidget(inputBox);

        connect(inputBox, &QLineEdit::returnPressed, this, &IRCBot::sendMessage);

        socket = new QSslSocket(this);
        connect(socket, &QSslSocket::readyRead, this, &IRCBot::readFromServer);
        connect(socket, &QSslSocket::encrypted, this, &IRCBot::onConnected);

        // Setup DB
        QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName("users.db");
        db.open();
        QSqlQuery query;
        query.exec("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)");

        // Connect to IRC
        socket->connectToHostEncrypted("irc.libera.chat", 6697);
    }

private slots:
    void onConnected() {
        socket->write("NICK " + nick.toUtf8() + "\r\n");
        socket->write("USER " + nick.toUtf8() + " 0 * :" + nick.toUtf8() + "\r\n");
        QTimer::singleShot(3000, [this]() {
            for (const QString &ch : joinedChannels)
                socket->write("JOIN " + ch.toUtf8() + "\r\n");
        });
    }


    void readFromServer() {
        while (socket->canReadLine()) {
            QString msg = QString::fromUtf8(socket->readLine()).trimmed();
            chatDisplay->append(msg);

            if (msg.startsWith("PING")) {
                socket->write("PONG :" + msg.section(":", 1).toUtf8() + "\r\n");
                continue;
            }

            if (!msg.contains("PRIVMSG")) continue;

            QString sender = msg.section('!', 0, 0).mid(1);
            QString target = msg.section("PRIVMSG ", 1).section(' ', 0, 0);
            QString content = msg.section(":", 2);

            bool isPrivate = !target.startsWith("#");
            QString displayPrefix = isPrivate ? "[PM] " : "[" + target + "] ";
            chatDisplay->append(displayPrefix + "<" + sender + "> " + content);

            // Handle commands
            if (content == "!help") {
                sendRaw("PRIVMSG " + (isPrivate ? sender : target) + " :Commands: !join #chan, !register <user> <pass>, !login <user> <pass>, !8ball <q>");
            } else if (content.startsWith("!join ")) {
                QString newChannel = content.section(" ", 1, 1);
                if (!joinedChannels.contains(newChannel)) {
                    joinedChannels.append(newChannel);
                    sendRaw("JOIN " + newChannel.toUtf8());
                    sendRaw("PRIVMSG " + (isPrivate ? sender : target) + " :Joining " + newChannel);
                }
            } else if (content.startsWith("!register")) {
                QStringList args = content.split(" ");
                if (args.size() == 3) {
                    sendRaw("PRIVMSG " + target.toUtf8() + " :" + (registerUser(args[1], args[2]) ? "User registered." : "Registration failed."));
                }
            } else if (content.startsWith("!login")) {
                QStringList args = content.split(" ");
                if (args.size() == 3) {
                    sendRaw("PRIVMSG " + target.toUtf8() + " :" + (loginUser(args[1], args[2]) ? "Login successful." : "Login failed."));
                }
            } else if (content.startsWith("!8ball")) {
                QStringList replies = {"Yes", "No", "Maybe", "Ask again", "Definitely", "I don't think so"};
                QString reply = replies.at(QRandomGenerator::global()->bounded(replies.size()));
                sendRaw("PRIVMSG " + (isPrivate ? sender : target) + " :" + reply);
            }
        }
    }


    void sendMessage() {
        QString text = inputBox->text();
        if (!text.isEmpty()) {
            sendRaw("PRIVMSG #testchannel :" + text.toUtf8());
            inputBox->clear();
        }
    }

private:
    QTextEdit *chatDisplay;
    QLineEdit *inputBox;
    QSslSocket *socket;
    QStringList joinedChannels = {"#testchannel"};  // default channel
    QString nick = "QtBot";


    void sendRaw(const QString &msg) {
        socket->write(msg.toUtf8() + "\r\n");
    }


    bool registerUser(const QString &user, const QString &pass) {
        QSqlQuery query;
        query.prepare("INSERT INTO users (username, password) VALUES (:u, :p)");
        query.bindValue(":u", user);
        query.bindValue(":p", pass);
        return query.exec();
    }

    bool loginUser(const QString &user, const QString &pass) {
        QSqlQuery query;
        query.prepare("SELECT * FROM users WHERE username = :u AND password = :p");
        query.bindValue(":u", user);
        query.bindValue(":p", pass);
        query.exec();
        return query.next();
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    IRCBot bot;
    bot.show();
    return app.exec();
}

#include "main.moc"
