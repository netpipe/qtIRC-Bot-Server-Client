// main.cpp - Qt IRC Client with full Channel tabs + Server tab input + DCC incoming/outgoing CHAT & SEND

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

    void sendRaw(const QString &msg) {
        socket->write(msg.toUtf8());
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

// === ChannelTab UI container ===
struct ChannelTab {
    QWidget *widget = nullptr;
    QTextEdit* chatLog = nullptr;
    QListWidget* userList = nullptr;
    QLineEdit* input = nullptr;
};

// === PrivateMessageTab UI container ===
struct PrivateMsgTab {
    QWidget *widget = nullptr;
    QTextEdit* chatLog = nullptr;
    QLineEdit* input = nullptr;
    QString peerNick;
    QString serverName;
    DccChatDialog *dccChat = nullptr; // optional DCC chat window if opened
};

class IrcClient : public QMainWindow {
    Q_OBJECT
public:
    IrcClient() {
        resize(1200, 800);
        setWindowTitle("Qt IRC Client with full Channel tabs and DCC support");

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
        q.exec("CREATE TABLE IF NOT EXISTS servers (name TEXT PRIMARY KEY, host TEXT, port INTEGER, ssl INTEGER)");
        q.exec("CREATE TABLE IF NOT EXISTS channels (server TEXT, channel TEXT)");

        loadServers();
    }

private:
    QTabWidget *tabs;
    QSqlDatabase db;

    // serverName -> socket
    QMap<QString, QTcpSocket*> serverSockets;
    // serverName -> server tab UI elements
    QMap<QString, QTextEdit*> serverTabs;
    QMap<QString, QLineEdit*> serverInputBoxes;

    // serverName -> channelName -> ChannelTab UI elements
    QMap<QString, QMap<QString, ChannelTab>> serverChannelTabs;

    // serverName+nick -> PrivateMsgTab UI elements
    QMap<QString, PrivateMsgTab> privateMsgTabs;

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
            q.prepare("INSERT OR REPLACE INTO servers VALUES (?, ?, ?, ?)");
            q.addBindValue(name->text());
            q.addBindValue(host->text());
            q.addBindValue(port->value());
            q.addBindValue(ssl->isChecked());
            q.exec();
            createServerTab(name->text(), host->text(), port->value(), ssl->isChecked());
        }
    }

    void createServerTab(const QString &name, const QString &host, int port, bool ssl) {
        QWidget *widget = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(widget);

        QTextEdit *log = new QTextEdit;
        log->setReadOnly(true);
        QLineEdit *input = new QLineEdit;

        layout->addWidget(log);
        layout->addWidget(input);

        tabs->addTab(widget, name);

        serverTabs[name] = log;
        serverInputBoxes[name] = input;

        QTcpSocket *socket = new QTcpSocket(this);
        serverSockets[name] = socket;

        connect(socket, &QTcpSocket::readyRead, this, [=]() {
            QByteArray data = socket->readAll();
            QList<QByteArray> lines = data.split('\n');
            for (auto &line : lines) {
                QString sline = QString::fromUtf8(line).trimmed();
                if (!sline.isEmpty()) processIrcLine(name, sline);
            }
        });

        connect(socket, &QTcpSocket::connected, this, [=]() {
            log->append("Connected to " + host);
            QString nick = "QtUser"; // you can extend to user input
            socket->write("NICK " + nick.toUtf8() + "\r\n");
            socket->write("USER " + nick.toUtf8() + " 0 * :Qt IRC Client\r\n");
        });

        connect(socket, &QTcpSocket::disconnected, this, [=]() {
            log->append("Disconnected.");
        });

        connect(input, &QLineEdit::returnPressed, this, [=]() {
            QString cmd = input->text().trimmed();
            if (cmd.isEmpty()) return;
            socket->write(cmd.toUtf8() + "\r\n");
            log->append("> " + cmd);
            input->clear();

            // Simple channel join command support to create channel tab:
            if (cmd.startsWith("JOIN ")) {
                QStringList parts = cmd.split(' ');
                if (parts.size() > 1) {
                    QString channel = parts[1];
                    if (!serverChannelTabs[name].contains(channel)) {
                        createChannelTab(name, channel, socket);
                    }
                }
            }
        });

        socket->connectToHost(host, port);
    }

    void createChannelTab(const QString &server, const QString &channel, QTcpSocket *socket) {
        if (serverChannelTabs[server].contains(channel)) {
            // Already exists, just switch to it
            for (int i = 0; i < tabs->count(); ++i) {
                if (tabs->tabText(i) == server + " " + channel) {
                    tabs->setCurrentIndex(i);
                    return;
                }
            }
            return;
        }

        QWidget *widget = new QWidget;
        QHBoxLayout *mainLayout = new QHBoxLayout(widget);

        // Chat log + input vertical layout
        QVBoxLayout *chatLayout = new QVBoxLayout;
        QTextEdit *chatLog = new QTextEdit;
        chatLog->setReadOnly(true);
        QLineEdit *input = new QLineEdit;
        chatLayout->addWidget(chatLog);
        chatLayout->addWidget(input);

        // User list
        QListWidget *userList = new QListWidget;
        userList->setMaximumWidth(150);

        mainLayout->addLayout(chatLayout);
        mainLayout->addWidget(userList);

        tabs->addTab(widget, server + " " + channel);
        tabs->setCurrentWidget(widget);

        ChannelTab ctab;
        ctab.widget = widget;
        ctab.chatLog = chatLog;
        ctab.input = input;
        ctab.userList = userList;
        serverChannelTabs[server][channel] = ctab;

        connect(input, &QLineEdit::returnPressed, this, [=]() {
            QString text = input->text().trimmed();
            if (text.isEmpty()) return;
            QString msg = "PRIVMSG " + channel + " :" + text + "\r\n";
            socket->write(msg.toUtf8());
            chatLog->append("<You> " + text);
            input->clear();
        });

        // Right click user list context menu for PM, DCC Chat, DCC Send
        userList->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(userList, &QListWidget::customContextMenuRequested, this, [=](const QPoint &pos) {
            QListWidgetItem *item = userList->itemAt(pos);
            if (!item) return;
            QString nick = item->text();
            QMenu menu;
            QAction *pm = menu.addAction("Private Message");
            QAction *dccChat = menu.addAction("Start DCC Chat");
            QAction *dccSend = menu.addAction("Send File (DCC SEND)");
            QAction *selected = menu.exec(userList->mapToGlobal(pos));
            if (!selected) return;

            if (selected == pm) {
                openPrivateMessage(server, nick);
            } else if (selected == dccChat) {
                initiateDccChat(server, nick);
            } else if (selected == dccSend) {
                initiateDccSend(server, nick);
            }
        });

        // Double-click username for private msg
        connect(userList, &QListWidget::itemDoubleClicked, this, [=](QListWidgetItem *item) {
            if (!item) return;
            openPrivateMessage(server, item->text());
        });
    }

    void openPrivateMessage(const QString &server, const QString &nick) {
        QString tabName = server + " PM " + nick;
        if (privateMsgTabs.contains(tabName)) {
            tabs->setCurrentWidget(privateMsgTabs[tabName].widget);
            return;
        }

        QWidget *widget = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(widget);
        QTextEdit *pmLog = new QTextEdit;
        pmLog->setReadOnly(true);
        QLineEdit *input = new QLineEdit;

        layout->addWidget(pmLog);
        layout->addWidget(input);

        tabs->addTab(widget, tabName);
        tabs->setCurrentWidget(widget);

        PrivateMsgTab pmTab;
        pmTab.widget = widget;
        pmTab.chatLog = pmLog;
        pmTab.input = input;
        pmTab.peerNick = nick;
        pmTab.serverName = server;
        pmTab.dccChat = nullptr;
        privateMsgTabs[tabName] = pmTab;

        QTcpSocket *sock = serverSockets.value(server, nullptr);
        if (!sock) return;

        connect(input, &QLineEdit::returnPressed, this, [=]() {
            QString text = input->text().trimmed();
            if (text.isEmpty()) return;
            QString msg = "PRIVMSG " + nick + " :" + text + "\r\n";
            sock->write(msg.toUtf8());
            pmLog->append("<You> " + text);
            input->clear();
        });
    }

    void initiateDccChat(const QString &server, const QString &nick) {
        QTcpSocket *sock = serverSockets.value(server, nullptr);
        if (!sock) return;

        // For simplicity, here we ask the user to input IP and port to connect to,
        // in a real client, you would send a DCC CHAT request to the user and listen for incoming connections.
        bool ok1, ok2;
        QString ip = QInputDialog::getText(this, "DCC Chat", "Enter IP address of peer:", QLineEdit::Normal, "", &ok1);
        int port = QInputDialog::getInt(this, "DCC Chat", "Enter port number:", 5000, 1, 65535, 1, &ok2);
        if (!ok1 || !ok2) return;

        DccChatDialog *dccChat = new DccChatDialog(nick, ip, port, this);
        dccChat->show();

        // Store dialog to PrivateMsgTab if open
        QString tabName = server + " PM " + nick;
        if (privateMsgTabs.contains(tabName)) {
            privateMsgTabs[tabName].dccChat = dccChat;
        }
    }

    void initiateDccSend(const QString &server, const QString &nick) {
        QTcpSocket *sock = serverSockets.value(server, nullptr);
        if (!sock) return;

        QString filePath = QFileDialog::getOpenFileName(this, "Select File to Send");
        if (filePath.isEmpty()) return;

        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, "Error", "Cannot open file for reading");
            return;
        }
        qint64 fileSize = file.size();

        // For simplicity, the client will listen on a random port and send DCC SEND request to peer
        QTcpServer *fileServer = new QTcpServer(this);
        if (!fileServer->listen(QHostAddress::Any, 0)) {
            QMessageBox::warning(this, "Error", "Cannot listen for file transfer");
            return;
        }
        quint16 port = fileServer->serverPort();

        // Convert IP to unsigned int format
        QHostAddress localAddr = fileServer->serverAddress();
        if (localAddr.isLoopback()) localAddr = QHostAddress(QHostAddress::LocalHost);
        quint32 ipInt = localAddr.toIPv4Address();

        // Build DCC SEND message (CTCP)
        QString fileName = QFileInfo(file).fileName();
        QString dccMsg = QString("PRIVMSG %1 :\x01DCC SEND %2 %3 %4 %5\x01\r\n")
                            .arg(nick)
                            .arg(fileName)
                            .arg(ipInt)
                            .arg(port)
                            .arg(fileSize);
        sock->write(dccMsg.toUtf8());

        // Accept connection and send file
        connect(fileServer, &QTcpServer::newConnection, this, [=]() mutable {
            QTcpSocket *conn = fileServer->nextPendingConnection();
            connect(conn, &QTcpSocket::disconnected, conn, &QTcpSocket::deleteLater);
            connect(conn, &QTcpSocket::disconnected, fileServer, &QTcpServer::close);

            // Send file data in chunks
            const qint64 chunkSize = 4096;
            while (!file.atEnd()) {
                QByteArray chunk = file.read(chunkSize);
                conn->write(chunk);
                conn->waitForBytesWritten();
            }
            conn->flush();
            file.close();
            QMessageBox::information(this, "File Transfer", "File sent successfully");
            fileServer->close();
            fileServer->deleteLater();
        });

        QMessageBox::information(this, "DCC SEND", QString("DCC SEND request sent to %1. Waiting for connection on port %2").arg(nick).arg(port));
    }

    QString prefixToNick(const QString &prefix) {
        return prefix.section('!', 0, 0);
    }

    void processIrcLine(const QString &server, const QString &line) {
        QTextEdit *log = serverTabs.value(server, nullptr);
        if (!log) return;

        log->append(line);

        // IRC message format:
        // [:prefix] command [params] :trailing

        QString prefix, command, params, trailing;
        QStringList parts;

        QString temp = line;

        if (temp.startsWith(':')) {
            prefix = temp.section(' ', 0, 0).mid(1);
            temp = temp.mid(prefix.length() + 2);
        }
        if (temp.contains(" :")) {
            params = temp.section(" :", 0, 0);
            trailing = temp.section(" :", 1);
        } else {
            params = temp;
            trailing.clear();
        }

        parts = params.split(' ', Qt::SkipEmptyParts);
        if (parts.size() > 0) command = parts[0];
        else command.clear();

        if (command == "PING") {
            // Reply with PONG
            QString pong = "PONG :" + trailing + "\r\n";
            serverSockets[server]->write(pong.toUtf8());
            return;
        }

        if (command == "PRIVMSG") {
            QString fromNick = prefixToNick(prefix);
            QString target = parts.size() > 1 ? parts[1] : "";

            // Detect CTCP DCC messages
            if (trailing.startsWith('\x01') && trailing.endsWith('\x01')) {
                QString ctcp = trailing.mid(1, trailing.length() - 2);
                if (ctcp.startsWith("DCC ")) {
                    handleDccRequest(server, fromNick, ctcp.mid(4));
                    return;
                }
            }

            if (target.startsWith('#')) {
                // Channel message
                if (serverChannelTabs[server].contains(target)) {
                    auto &tab = serverChannelTabs[server][target];
                    tab.chatLog->append(QString("<%1> %2").arg(fromNick, trailing));
                    return;
                }
            } else {
                // Private message
                QString pmTabName = server + " PM " + fromNick;
                if (!privateMsgTabs.contains(pmTabName)) {
                    openPrivateMessage(server, fromNick);
                }
                privateMsgTabs[pmTabName].chatLog->append(QString("<%1> %2").arg(fromNick, trailing));
            }
            return;
        }

        if (command == "353") {
            // Names list
            // Format: :server 353 nick = #channel :user1 user2 user3
            if (parts.size() >= 4) {
                QString channel = parts[3];
                QString names = trailing;
                if (serverChannelTabs[server].contains(channel)) {
                    auto &tab = serverChannelTabs[server][channel];
                    tab.userList->clear();
                    QStringList users = names.split(' ', Qt::SkipEmptyParts);
                    for (QString u : users) {
                        // strip mode prefixes like @, +
                        if (!u.isEmpty() && (u[0] == '@' || u[0] == '+')) u = u.mid(1);
                        tab.userList->addItem(u);
                    }
                }
            }
            return;
        }

        if (command == "JOIN") {
            // Someone joined a channel
            QString nick = prefixToNick(prefix);
            QString channel = trailing.isEmpty() ? parts.value(1) : trailing;
            if (serverChannelTabs[server].contains(channel)) {
                auto &tab = serverChannelTabs[server][channel];
                tab.chatLog->append(QString("*** %1 has joined %2").arg(nick, channel));
                // Add to user list
                bool found = false;
                for (int i = 0; i < tab.userList->count(); ++i) {
                    if (tab.userList->item(i)->text() == nick) { found = true; break; }
                }
                if (!found) tab.userList->addItem(nick);
            }
            return;
        }

        if (command == "PART") {
            QString nick = prefixToNick(prefix);
            QString channel = parts.value(1);
            if (serverChannelTabs[server].contains(channel)) {
                auto &tab = serverChannelTabs[server][channel];
                tab.chatLog->append(QString("*** %1 has left %2").arg(nick, channel));
                // Remove from user list
                for (int i = 0; i < tab.userList->count(); ++i) {
                    if (tab.userList->item(i)->text() == nick) {
                        delete tab.userList->takeItem(i);
                        break;
                    }
                }
            }
            return;
        }

        if (command == "NOTICE") {
            QString fromNick = prefixToNick(prefix);
            QString target = parts.size() > 1 ? parts[1] : "";
            if (target == server) {
                if (log) log->append(QString("-Notice- %1").arg(trailing));
            }
            return;
        }
    }

    void handleDccRequest(const QString &server, const QString &fromNick, const QString &dccMsg) {
        QStringList parts = dccMsg.split(' ');
        if (parts.size() < 4) return;

        QString type = parts[0];
        if (type == "CHAT") {
            // DCC CHAT request: CHAT ip port
            if (parts.size() < 3) return;
            quint32 ipInt = parts[1].toUInt();
            quint16 port = parts[2].toUShort();
            QHostAddress ipAddr(ipInt);

            DccChatDialog *dccChat = new DccChatDialog(fromNick, ipAddr.toString(), port, this);
            dccChat->show();

            QString tabName = server + " PM " + fromNick;
            if (!privateMsgTabs.contains(tabName)) {
                openPrivateMessage(server, fromNick);
            }
            privateMsgTabs[tabName].dccChat = dccChat;

        } else if (type == "SEND") {
            // DCC SEND: SEND filename ip port filesize
            if (parts.size() < 5) return;
            QString fileName = parts[1];
            quint32 ipInt = parts[2].toUInt();
            quint16 port = parts[3].toUShort();
            quint64 fileSize = parts[4].toULongLong();
            QHostAddress ipAddr(ipInt);

            QString saveFile = QFileDialog::getSaveFileName(this, "Save incoming file", fileName);
            if (saveFile.isEmpty()) return;

            DccFileDialog *fileDlg = new DccFileDialog(fromNick, saveFile, ipAddr.toString(), port, fileSize, this);
            fileDlg->show();
        }
    }
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    IrcClient w;
    w.show();
    return app.exec();
}

#include "main.moc"
