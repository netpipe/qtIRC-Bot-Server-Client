// main.cpp - IRC Client with DCC Chat and File support added
// Qt 5.12+, requires core network sql widgets

#include <QtCore>
#include <QtNetwork>
#include <QtWidgets>
#include <QtSql>
#include <QFileDialog>

// === DccChatDialog ===
class DccChatDialog : public QDialog {
    Q_OBJECT
public:
    DccChatDialog(const QString &peerNick, const QString &ip, quint16 port, QWidget *parent = nullptr)
        : QDialog(parent), peerNick(peerNick), ip(ip), port(port) {
        setWindowTitle(QString("DCC Chat with %1").arg(peerNick));
        resize(400, 300);
        QVBoxLayout *layout = new QVBoxLayout(this);
        chatLog = new QTextEdit; chatLog->setReadOnly(true);
        input = new QLineEdit;
        QPushButton *sendBtn = new QPushButton("Send");
        layout->addWidget(chatLog);
        layout->addWidget(input);
        layout->addWidget(sendBtn);

        socket = new QTcpSocket(this);
        connect(socket, &QTcpSocket::readyRead, this, &DccChatDialog::onReadyRead);
        connect(sendBtn, &QPushButton::clicked, this, &DccChatDialog::sendMessage);
        connect(input, &QLineEdit::returnPressed, this, &DccChatDialog::sendMessage);

        socket->connectToHost(ip, port);
        if (!socket->waitForConnected(5000)) {
            chatLog->append("Failed to connect to " + ip + ":" + QString::number(port));
            input->setDisabled(true);
            sendBtn->setDisabled(true);
        }
    }

private slots:
    void onReadyRead() {
        QByteArray data = socket->readAll();
        chatLog->append(QString("<%1> %2").arg(peerNick, QString::fromUtf8(data)));
    }

    void sendMessage() {
        QString text = input->text().trimmed();
        if (text.isEmpty()) return;
        socket->write(text.toUtf8());
        chatLog->append(QString("<You> %1").arg(text));
        input->clear();
    }

private:
    QString peerNick, ip;
    quint16 port;
    QTcpSocket *socket;
    QTextEdit *chatLog;
    QLineEdit *input;
};

// === DccFileDialog ===
class DccFileDialog : public QDialog {
    Q_OBJECT
public:
    DccFileDialog(const QString &peerNick, const QString &fileName, const QString &ip, quint16 port, quint64 fileSize, QWidget *parent = nullptr)
        : QDialog(parent), peerNick(peerNick), fileName(fileName), ip(ip), port(port), fileSize(fileSize), bytesReceived(0) {
        setWindowTitle(QString("DCC File Receive from %1").arg(peerNick));
        resize(400, 100);
        QVBoxLayout *layout = new QVBoxLayout(this);
        progressBar = new QProgressBar;
        progressBar->setRange(0, 100);
        QPushButton *cancelBtn = new QPushButton("Cancel");
        layout->addWidget(progressBar);
        layout->addWidget(cancelBtn);

        socket = new QTcpSocket(this);
        file.setFileName(fileName);
        if (!file.open(QIODevice::WriteOnly)) {
            progressBar->setFormat("Failed to open file for writing");
            cancelBtn->setText("Close");
            cancelBtn->setEnabled(true);
        } else {
            socket->connectToHost(ip, port);
            connect(socket, &QTcpSocket::readyRead, this, &DccFileDialog::onReadyRead);
            connect(socket, &QTcpSocket::connected, this, &DccFileDialog::onConnected);
            connect(socket, &QTcpSocket::disconnected, this, &DccFileDialog::onDisconnected);
            connect(cancelBtn, &QPushButton::clicked, this, &DccFileDialog::reject);
        }
        connect(cancelBtn, &QPushButton::clicked, this, &DccFileDialog::reject);
    }

private slots:
    void onConnected() {
        progressBar->setFormat("Connected. Receiving...");
    }

    void onReadyRead() {
        QByteArray data = socket->readAll();
        qint64 written = file.write(data);
        if (written > 0) {
            bytesReceived += written;
            int percent = (int)((bytesReceived * 100) / fileSize);
            progressBar->setValue(percent);
            progressBar->setFormat(QString("%1% (%2 / %3 bytes)").arg(percent).arg(bytesReceived).arg(fileSize));
        }
    }

    void onDisconnected() {
        file.close();
        progressBar->setFormat("Transfer complete or disconnected");
    }

private:
    QString peerNick, fileName, ip;
    quint16 port;
    quint64 fileSize;
    qint64 bytesReceived;
    QTcpSocket *socket;
    QFile file;
    QProgressBar *progressBar;
};


// === IRC Client Main ===
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
        setWindowTitle("QtIRC Client with DCC");

        tabs = new QTabWidget(this);
        setCentralWidget(tabs);

        QMenu *fileMenu = menuBar()->addMenu("Servers");
        QAction *addServer = new QAction("Add Server", this);
        connect(addServer, &QAction::triggered, this, &IrcClient::addServerDialog);
        fileMenu->addAction(addServer);

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
    QMap<QString, QTcpSocket*> serverSockets; // server name to socket

    void loadServers() {
        QSqlQuery q("SELECT name, host, port, ssl FROM servers");
        while (q.next()) {
            QString name = q.value(0).toString();
            QString host = q.value(1).toString();
            int port = q.value(2).toInt();
            bool ssl = q.value(3).toBool();
            createServerTab(name, host, port, ssl);
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
            createServerTab(name->text(), host->text(), port->value(), ssl->isChecked());
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
            QAction *pm = menu.addAction("Private Message");
            connect(pm, &QAction::triggered, [=]() {
                openPrivateMessage(server, item->text());
            });
            menu.exec(userList->mapToGlobal(pos));
        });

        // Double-click username for private msg
        connect(userList, &QListWidget::itemDoubleClicked, [=](QListWidgetItem *item) {
            if (item) openPrivateMessage(server, item->text());
        });
    }

    void createServerTab(const QString &name, const QString &host, int port, bool ssl) {
        QTextEdit *tab = new QTextEdit;
        tab->setReadOnly(true);
        tabs->addTab(tab, name);
        serverTabs[name] = tab;

        QTcpSocket *socket = new QTcpSocket(this);
        serverSockets[name] = socket;

        connect(socket, &QTcpSocket::readyRead, [=]() {
            QByteArray data = socket->readAll();
            QList<QByteArray> lines = data.split('\n');
            for (auto &line : lines) {
                QString sline = QString::fromUtf8(line).trimmed();
                if (!sline.isEmpty()) processIrcLine(name, sline);
            }
        });

        connect(socket, &QTcpSocket::connected, [=]() {
            tab->append("Connected to " + host);
            socket->write("NICK QtUser\r\nUSER QtUser 0 * :Qt IRC Client\r\n");
        });

        connect(socket, &QTcpSocket::disconnected, [=]() {
            tab->append("Disconnected.");
        });

        socket->connectToHost(host, port);
    }

    void openPrivateMessage(const QString &server, const QString &nick) {
        QString tabName = server + " PM " + nick;
        // Check if tab exists
        for (int i = 0; i < tabs->count(); ++i) {
            if (tabs->tabText(i) == tabName) {
                tabs->setCurrentIndex(i);
                return;
            }
        }
        // New PM tab
        QTextEdit *pmLog = new QTextEdit;
        pmLog->setReadOnly(true);
        QLineEdit *input = new QLineEdit;
        QWidget *pmWidget = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(pmWidget);
        layout->addWidget(pmLog);
        layout->addWidget(input);
        tabs->addTab(pmWidget, tabName);
        tabs->setCurrentWidget(pmWidget);

        QTcpSocket *sock = serverSockets.value(server, nullptr);
        if (!sock) return;

        connect(input, &QLineEdit::returnPressed, [=]() {
            QString text = input->text();
            if (text.isEmpty()) return;
            QString msg = "PRIVMSG " + nick + " :" + text + "\r\n";
            sock->write(msg.toUtf8());
            pmLog->append("<You> " + text);
            input->clear();
        });
    }

    QString prefixToNick(const QString &prefix) {
        return prefix.section('!', 0, 0);
    }

    void processIrcLine(const QString &serverName, const QString &line) {
        QTextEdit *tab = serverTabs.value(serverName, nullptr);
        if (!tab) return;

        QString prefix, command;
        QStringList params;

        QString l = line.trimmed();

        if (l.startsWith(':')) {
            int sp = l.indexOf(' ');
            prefix = l.mid(1, sp - 1);
            l = l.mid(sp + 1);
        }

        int sp2 = l.indexOf(' ');
        if (sp2 == -1) {
            command = l;
        } else {
            command = l.left(sp2);
            QString rest = l.mid(sp2 + 1);
            if (rest.contains(':')) {
                int colonPos = rest.indexOf(':');
                QString beforeColon = rest.left(colonPos).trimmed();
                QString afterColon = rest.mid(colonPos + 1);
                params = beforeColon.split(' ', QString::SkipEmptyParts);
                params.append(afterColon);
            } else {
                params = rest.split(' ', QString::SkipEmptyParts);
            }
        }

        // Debug output
        tab->append(QString("<-- %1").arg(line));

        // Handle commands
        if (command == "PING" && !params.isEmpty()) {
            serverSockets[serverName]->write("PONG :" + params.last().toUtf8() + "\r\n");
        }
        else if (command == "001") {
            // Welcome message
            if (params.size() >= 1) {
                QString nick = params[0];
                tab->append("Welcome " + nick);
            }
        }
        else if (command == "JOIN" && !prefix.isEmpty()) {
            QString nick = prefixToNick(prefix);
            QString channel = params.isEmpty() ? "" : params[0];
            if (!channel.isEmpty()) {
                tab->append(QString("%1 joined %2").arg(nick, channel));
                if (!serverChannelTabs[serverName].contains(channel)) {
                    createChannelTab(serverName, channel, serverSockets[serverName]);
                }
                auto &ctab = serverChannelTabs[serverName][channel];
                ctab.chatLog->append(QString("%1 joined").arg(nick));
                if (!ctab.userList->findItems(nick, Qt::MatchExactly).count())
                    ctab.userList->addItem(nick);
            }
        }
        else if (command == "PART" && !prefix.isEmpty()) {
            QString nick = prefixToNick(prefix);
            QString channel = params.isEmpty() ? "" : params[0];
            if (!channel.isEmpty() && serverChannelTabs[serverName].contains(channel)) {
                auto &ctab = serverChannelTabs[serverName][channel];
                ctab.chatLog->append(QString("%1 left").arg(nick));
                QList<QListWidgetItem*> found = ctab.userList->findItems(nick, Qt::MatchExactly);
                for (auto item : found) ctab.userList->takeItem(ctab.userList->row(item));
            }
        }
        else if (command == "353") {
            // NAMES list reply
            if (params.size() >= 4) {
                QString channel = params[2];
                QStringList users = params[3].split(' ');
                if (serverChannelTabs[serverName].contains(channel)) {
                    auto &ctab = serverChannelTabs[serverName][channel];
                    for (const QString &u : users) {
                        QString user = u.trimmed();
                        if (!user.isEmpty() && !ctab.userList->findItems(user, Qt::MatchExactly).count()) {
                            ctab.userList->addItem(user);
                        }
                    }
                }
            }
        }
        else if (command == "PRIVMSG" && params.size() >= 2) {
            QString fromNick = prefixToNick(prefix);
            QString target = params[0];
            QString msg = params[1];

            if (serverChannelTabs[serverName].contains(target)) {
                auto &ctab = serverChannelTabs[serverName][target];
                ctab.chatLog->append(QString("<%1> %2").arg(fromNick, msg));
            } else {
                // PM message
                QString tabName = serverName + " PM " + fromNick;
                QTextEdit *pmLog = nullptr;
                for (int i = 0; i < tabs->count(); ++i) {
                    if (tabs->tabText(i) == tabName) {
                        QWidget *w = tabs->widget(i);
                        pmLog = w->findChild<QTextEdit*>();
                        tabs->setCurrentIndex(i);
                        break;
                    }
                }
                if (!pmLog) {
                    openPrivateMessage(serverName, fromNick);
                    for (int i = 0; i < tabs->count(); ++i) {
                        if (tabs->tabText(i) == tabName) {
                            QWidget *w = tabs->widget(i);
                            pmLog = w->findChild<QTextEdit*>();
                            break;
                        }
                    }
                }
                if (pmLog) {
                    pmLog->append(QString("<%1> %2").arg(fromNick, msg));
                }
            }
        }
        else if (command == "DCC" && params.size() >= 2) {
            QString dccType = params[1];
            QString senderNick = prefixToNick(prefix);

            QString restParams = line.section("DCC", 1).trimmed();
            QStringList dccParts = restParams.split(' ', QString::SkipEmptyParts);
            // dccParts[0] = CHAT or SEND etc.

            if (dccType == "CHAT" && dccParts.size() >= 4) {
                // Format: CHAT filename ip port
                // IP sent as unsigned int
                bool ok1, ok2;
                quint32 ipNum = dccParts[2].toUInt(&ok1);
                quint16 port = dccParts[3].toUShort(&ok2);
                if (ok1 && ok2) {
                    QString ip = QString("%1.%2.%3.%4")
                        .arg((ipNum >> 24) & 0xFF)
                        .arg((ipNum >> 16) & 0xFF)
                        .arg((ipNum >> 8) & 0xFF)
                        .arg(ipNum & 0xFF);

                    QMessageBox::StandardButton reply =
                        QMessageBox::question(this, "DCC Chat Request",
                            QString("%1 wants to start a DCC Chat.\nAccept?").arg(senderNick));
                    if (reply == QMessageBox::Yes) {
                        auto dlg = new DccChatDialog(senderNick, ip, port, this);
                        dlg->show();
                    }
                }
            }
            else if (dccType == "SEND" && dccParts.size() >= 6) {
                // Format: SEND filename ip port size token
                QString fileName = dccParts[1];
                bool ok1, ok2, ok3;
                quint32 ipNum = dccParts[2].toUInt(&ok1);
                quint16 port = dccParts[3].toUShort(&ok2);
                quint64 fileSize = dccParts[4].toULongLong(&ok3);

                if (ok1 && ok2 && ok3) {
                    QString ip = QString("%1.%2.%3.%4")
                        .arg((ipNum >> 24) & 0xFF)
                        .arg((ipNum >> 16) & 0xFF)
                        .arg((ipNum >> 8) & 0xFF)
                        .arg(ipNum & 0xFF);

                    QString savePath = QFileDialog::getSaveFileName(this, "Save File", fileName);
                    if (!savePath.isEmpty()) {
                        auto dlg = new DccFileDialog(senderNick, savePath, ip, port, fileSize, this);
                        dlg->show();
                    }
                }
            }
        }
    }
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    IrcClient client;
    client.show();
    return app.exec();
}

#include "main.moc"
