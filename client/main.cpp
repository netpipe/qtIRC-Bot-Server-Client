// IrcClient.cpp - Single-file IRC Client with Qt GUI, multiple server and channel tabs, user list with color, and advanced IRC features
// Qt 5.12+, use with: QT += core network sql widgets

#include <QtCore>
#include <QtNetwork>
#include <QtWidgets>
#include <QtSql>
#include <QFile>

struct IrcUser {
    QString nick;
    QColor color;
    bool isOp = false;
    bool isVoice = false;
};

struct ChannelTab {
    QTextEdit* chatLog;
    QListWidget* userList;
    QLineEdit* input;
};

class IrcClient : public QMainWindow {
    Q_OBJECT
public:
    IrcClient() {
        resize(1100, 700);
        setWindowTitle("QtIRC Client");

        tabs = new QTabWidget(this);
        setCentralWidget(tabs);

        QMenu *fileMenu = menuBar()->addMenu("Servers");
        QAction *addServer = new QAction("Add Server", this);
        fileMenu->addAction(addServer);
        connect(addServer, &QAction::triggered, this, &IrcClient::addServerDialog);

        db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName("ircclient.db");
        db.open();
        QSqlQuery q;
        q.exec("CREATE TABLE IF NOT EXISTS servers (name TEXT, host TEXT, port INTEGER, ssl INTEGER)");
        q.exec("CREATE TABLE IF NOT EXISTS channels (server TEXT, channel TEXT)");

        loadServers();
    }

private:
    QTabWidget *tabs;
    QSqlDatabase db;
    QMap<QString, QMap<QString, ChannelTab>> serverChannelTabs; // server -> channel -> UI elements
    QMap<QString, QTextEdit*> serverTabs; // server -> server tab

    void loadServers() {
        QSqlQuery q("SELECT name, host, port, ssl FROM servers");
        while (q.next()) {
            QString name = q.value(0).toString();
            QString host = q.value(1).toString();
            int port = q.value(2).toInt();
            bool ssl = q.value(3).toBool();

            QWidget *serverEntry = new QWidget;
            QHBoxLayout *layout = new QHBoxLayout(serverEntry);
            QLabel *label = new QLabel(name + " (" + host + ":" + QString::number(port) + (ssl ? " SSL)" : ")"));
            QPushButton *connectBtn = new QPushButton("Connect");
            layout->addWidget(label);
            layout->addWidget(connectBtn);
            QWidget *tab = new QWidget;
            QVBoxLayout *tabLayout = new QVBoxLayout(tab);
            tabLayout->addWidget(serverEntry);
            tabs->addTab(tab, name);

            connect(connectBtn, &QPushButton::clicked, [=]() {
                createServerTab(name, host, port, ssl);
            });
        }
    }

    void addServerDialog() {
        QDialog d(this);
        d.setWindowTitle("Add Server");
        QFormLayout form(&d);
        QLineEdit *name = new QLineEdit, *host = new QLineEdit;
        QSpinBox *port = new QSpinBox; port->setRange(1, 65535); port->setValue(6667);
        QCheckBox *ssl = new QCheckBox("Use SSL");
        form.addRow("Name:", name);
        form.addRow("Host:", host);
        form.addRow("Port:", port);
        form.addRow("", ssl);

        QPushButton *ok = new QPushButton("Add");
        form.addWidget(ok);
        connect(ok, &QPushButton::clicked, &d, &QDialog::accept);

        if (d.exec() == QDialog::Accepted) {
            QSqlQuery q;
            q.prepare("INSERT INTO servers VALUES (?, ?, ?, ?)");
            q.addBindValue(name->text());
            q.addBindValue(host->text());
            q.addBindValue(port->value());
            q.addBindValue(ssl->isChecked());
            q.exec();
            loadServers();
        }
    }

    void createChannelTab(const QString &server, const QString &channel, QTcpSocket* sock) {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);

        QTextEdit *chatLog = new QTextEdit;
        chatLog->setReadOnly(true);
        QListWidget *userList = new QListWidget;
        QSplitter *split = new QSplitter;
        split->addWidget(chatLog);
        split->addWidget(userList);
        split->setStretchFactor(0, 3);
        split->setStretchFactor(1, 1);

        QLineEdit *input = new QLineEdit;
        layout->addWidget(split);
        layout->addWidget(input);

        tabs->addTab(tab, server + ": " + channel);

        ChannelTab ch = { chatLog, userList, input };
        serverChannelTabs[server][channel] = ch;

        connect(input, &QLineEdit::returnPressed, [=]() {
            QString text = input->text();
            if (!text.isEmpty()) {
                sock->write(("PRIVMSG " + channel + " :" + text + "\r\n").toUtf8());
                chatLog->append("<You> " + text);
                input->clear();
            }
        });

        userList->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(userList, &QListWidget::customContextMenuRequested, [=](const QPoint &pos) {
            QListWidgetItem *item = userList->itemAt(pos);
            if (!item) return;
            QMenu menu;
            QAction *ping = menu.addAction("Ping");
            QAction *whois = menu.addAction("Whois");
            QAction *act = menu.exec(userList->mapToGlobal(pos));
            if (act == ping) sock->write(QString("PING :%1\r\n").arg(item->text()).toUtf8());
            if (act == whois) sock->write(QString("WHOIS %1\r\n").arg(item->text()).toUtf8());
        });
    }

    void createServerTab(const QString &name, const QString &host, int port, bool ssl) {
        QTcpSocket *sock = ssl ? new QSslSocket : new QTcpSocket;
        sock->connectToHost(host, port);
        if (ssl) static_cast<QSslSocket*>(sock)->startClientEncryption();

        QString nick = "QtUser" + QString::number(qrand() % 1000);
        QString user = "user";

        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);
        QTextEdit *serverLog = new QTextEdit;
        QLineEdit *serverInput = new QLineEdit;
        serverLog->setReadOnly(true);
        layout->addWidget(serverLog);
        layout->addWidget(serverInput);
        tabs->addTab(tab, name + ": --Server--");
        serverTabs[name] = serverLog;

        connect(serverInput, &QLineEdit::returnPressed, [=]() {
            QString text = serverInput->text();
            if (text.startsWith("/join ")) {
                QString chan = text.section(' ', 1, 1);
                sock->write(QString("JOIN %1\r\n").arg(chan).toUtf8());
                QMetaObject::invokeMethod(this, [=]() {
                    createChannelTab(name, chan, sock);
                }, Qt::QueuedConnection);
            } else if (text.startsWith("/msg ")) {
                QString target = text.section(' ', 1, 1);
                QString msg = text.section(' ', 2);
                sock->write(QString("PRIVMSG %1 :%2\r\n").arg(target, msg).toUtf8());
            } else if (text.startsWith("/whois ")) {
                QString who = text.section(' ', 1, 1);
                sock->write(QString("WHOIS %1\r\n").arg(who).toUtf8());
            } else {
                sock->write((text + "\r\n").toUtf8());
            }
            serverInput->clear();
        });

        QObject::connect(sock, &QTcpSocket::connected, [=]() {
            sock->write(QString("NICK %1\r\nUSER %2 0 * :Qt Client\r\n").arg(nick, user).toUtf8());
        });

        QThread *thread = QThread::create([=]() {
            QEventLoop loop;
            QObject temp;
            QObject::connect(sock, &QTcpSocket::readyRead, &temp, [=]() {
                while (sock->canReadLine()) {
                    QString line = QString::fromUtf8(sock->readLine()).trimmed();
                    qDebug() << line;

                    if (serverTabs.contains(name)) {
                        QMetaObject::invokeMethod(serverTabs[name], [=]() {
                            serverTabs[name]->append(line);
                        }, Qt::QueuedConnection);
                    }

                    if (line.startsWith("PING")) {
                        QString resp = "PONG" + line.mid(4);
                        sock->write((resp + "\r\n").toUtf8());
                    }

                    if (line.contains(" PRIVMSG ")) {
                        QString chan = line.section(" PRIVMSG ", 1).section(' ', 0, 0);
                        QString nick = line.section(':', 1, 1).section('!', 0, 0);
                        QString msg = line.section(" :", 2);
                        if (serverChannelTabs[name].contains(chan))
                            QMetaObject::invokeMethod(serverChannelTabs[name][chan].chatLog, [=]() {
                                serverChannelTabs[name][chan].chatLog->append("<" + nick + "> " + msg);
                            }, Qt::QueuedConnection);
                    }
                    else if (line.contains(" 332 ")) { // topic
                        QString chan = line.section(' ', 3, 3);
                        QString topic = line.section(" :", 1);
                        if (serverChannelTabs[name].contains(chan))
                            QMetaObject::invokeMethod(serverChannelTabs[name][chan].chatLog, [=]() {
                                serverChannelTabs[name][chan].chatLog->append("Topic: " + topic);
                            }, Qt::QueuedConnection);
                    }
                    else if (line.contains(" 353 ")) { // NAMES
                        QString chan = line.section(' ', 4, 4);
                        QStringList nicks = line.section(" :", 1).split(' ');
                        if (serverChannelTabs[name].contains(chan))
                            QMetaObject::invokeMethod(serverChannelTabs[name][chan].userList, [=]() {
                                auto &ul = serverChannelTabs[name][chan].userList;
                                ul->clear();
                                for (const QString &nick : nicks) {
                                    QListWidgetItem *item = new QListWidgetItem(nick);
                                    QColor c = QColor::fromHsv(qrand() % 360, 255, 200);
                                    item->setForeground(c);
                                    ul->addItem(item);
                                }
                            }, Qt::QueuedConnection);
                    }

                    if (line.contains(" 001 ")) {
                        QSqlQuery q;
                        q.prepare("SELECT channel FROM channels WHERE server=?");
                        q.addBindValue(name);
                        q.exec();
                        while (q.next()) {
                            QString chan = q.value(0).toString();
                            sock->write(QString("JOIN %1\r\n").arg(chan).toUtf8());
                            QMetaObject::invokeMethod(this, [=]() {
                                createChannelTab(name, chan, sock);
                            }, Qt::QueuedConnection);
                        }
                    }
                }
            });
            loop.exec();
        });
        thread->start();
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    IrcClient client;
    client.show();
    return app.exec();
}

#include "main.moc"
