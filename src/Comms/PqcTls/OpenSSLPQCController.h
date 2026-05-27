/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#pragma once

#include <QtCore/QObject>
#include <QtCore/QLoggingCategory>
#include <QtCore/QFile>
#include <QtCore/QStandardPaths>
#include <QtCore/QMutex>
#include <QtCore/QSocketNotifier>
#include <QtCore/QByteArray>
#include <QtCore/QThread>
#include "pqc_tls_wrapper.h"
#if defined(Q_OS_ANDROID)
#include <QtCore/QJniObject>
#include "src/Android/AndroidInterface.h"
#endif

// Forward declaration
extern "C" {
typedef struct pqc_tls_ctx_t pqc_tls_ctx_t;
}

class PQCTLSConnectionWorker;

Q_DECLARE_LOGGING_CATEGORY(OpenSSLPQCControllerLog)

/// OpenSSL PQC Settings - Singleton for QML/C++ integration
/// Location: src/Comms/PqcTls/OpenSSLPQCController.h
/// Purpose: UI state management and command invocation from QML
/// Note: This is a technology demonstration implementation with no dependency on existing communication links
class OpenSSLPQCController : public QObject
{
    Q_OBJECT

public:
    explicit OpenSSLPQCController(QObject *parent = nullptr);
    ~OpenSSLPQCController();

    // ========== Server Configuration Properties ==========
    Q_PROPERTY(QString  serverIpAddress        READ serverIpAddress        WRITE setServerIpAddress        NOTIFY serverIpAddressChanged)
    Q_PROPERTY(QString  serverPortNumber       READ serverPortNumber       WRITE setServerPortNumber       NOTIFY serverPortNumberChanged)
    Q_PROPERTY(bool     serverConnected        READ serverConnected        WRITE setServerConnected        NOTIFY serverConnectedChanged)

    // ========== Routing Configuration Properties ==========
    Q_PROPERTY(QString  routingPortNumber      READ routingPortNumber      WRITE setRoutingPortNumber      NOTIFY routingPortNumberChanged)
    Q_PROPERTY(bool     routingConnected       READ routingConnected       WRITE setRoutingConnected       NOTIFY routingConnectedChanged)

    // ========== Credential Information Properties ==========
    Q_PROPERTY(QString  caBundleFilePath       READ caBundleFilePath       WRITE setCaBundleFilePath       NOTIFY caBundleFilePathChanged)
    Q_PROPERTY(QString  clientCertFilePath     READ clientCertFilePath     WRITE setClientCertFilePath     NOTIFY clientCertFilePathChanged)

    // ========== TLS Log Buffer Property ==========
    Q_PROPERTY(QString  tlsLogBuffer           READ tlsLogBuffer                                           NOTIFY tlsLogBufferChanged)

    // ========== Raw & Decrypted Packet Viewer Properties ==========
    Q_PROPERTY(QString  rawPacketHex           READ rawPacketHex                                           NOTIFY rawPacketHexChanged)
    Q_PROPERTY(QString  decryptedPacketHex     READ decryptedPacketHex                                     NOTIFY decryptedPacketHexChanged)

    // ========== TLS HandShake Information Properties ==========
    Q_PROPERTY(QString  tlsVersion             READ tlsVersion                                             NOTIFY tlsVersionChanged)
    Q_PROPERTY(QString  tlsCipher              READ tlsCipher                                              NOTIFY tlsCipherChanged)
    Q_PROPERTY(QString  tlsKeyExchange         READ tlsKeyExchange                                         NOTIFY tlsKeyExchangeChanged)
    Q_PROPERTY(QString  tlsServerSig           READ tlsServerSig                                           NOTIFY tlsServerSigChanged)
    Q_PROPERTY(QString  tlsServerPubKey        READ tlsServerPubKey                                        NOTIFY tlsServerPubKeyChanged)

    // ========== Getter Methods ==========
    QString serverIpAddress() const { return _serverIpAddress; }
    QString serverPortNumber() const { return _serverPortNumber; }
    bool serverConnected() const { return _serverConnected; }
    
    QString routingPortNumber() const { return _routingPortNumber; }
    bool routingConnected() const { return _routingConnected; }
    
    QString caBundleFilePath() const { return _caBundleFilePath; }
    QString clientCertFilePath() const { return _clientCertFilePath; }

    // ========== TLS Log Buffer Getter ==========
    QString tlsLogBuffer() const { return _tlsLogBuffer; }

    // ========== Raw & Decrypted Packet Hex Getters ==========
    QString rawPacketHex() const { return _rawPacketHex; }
    QString decryptedPacketHex() const { return _decryptedPacketHex; }

    // ========== TLS HandShake Information Getters ==========
    QString tlsVersion() const { return _tlsVersion; }
    QString tlsCipher() const { return _tlsCipher; }
    QString tlsKeyExchange() const { return _tlsKeyExchange; }
    QString tlsServerSig() const { return _tlsServerSig; }
    QString tlsServerPubKey() const { return _tlsServerPubKey; }

    // ========== Setter Methods ==========
    void setServerIpAddress(const QString& address);
    void setServerPortNumber(const QString& port);
    void setServerConnected(bool connected);
    
    void setRoutingPortNumber(const QString& port);
    void setRoutingConnected(bool connected);
    
    void setCaBundleFilePath(const QString& path);
    void setClientCertFilePath(const QString& path);

    // ========== Connection Methods (Invokable from QML) ==========
    Q_INVOKABLE void connectToServer();
    Q_INVOKABLE void disconnectFromServer();
    
    Q_INVOKABLE void routeConnection();
    Q_INVOKABLE void disconnectRouting();

    // ========== File Copy Method (Invokable from QML) ==========
    Q_INVOKABLE QString copyAndGetAbsolutePath(const QString& contentUri, const QString& filename);

    // ========== File Import Methods (Android) ==========
    Q_INVOKABLE void callOpenPQCFileImportDialog(const QString& targetFilename);

    // ========== PQC TLS Data Read/Write Methods ==========
    Q_INVOKABLE QByteArray readData(int maxSize = 4096);
    Q_INVOKABLE int writeData(const QByteArray& data);

    // ========== TLS Logging Callback ==========
    static void logCallback(void* userData, const char* msg);

signals:
    void serverIpAddressChanged(const QString& address);
    void serverPortNumberChanged(const QString& port);
    void serverConnectedChanged(bool connected);
    
    void routingPortNumberChanged(const QString& port);
    void routingConnectedChanged(bool connected);
    
    void caBundleFilePathChanged(const QString& path);
    void clientCertFilePathChanged(const QString& path);
    
    // ========== PQC TLS Data Transfer Signals ==========
    void dataReceived(const QByteArray& data);
    void dataSent(int bytes);
    void connectionError(const QString& errorMsg);
    
    // ========== PQC TLS Logging Signal ==========
    void tlsLogMessage(const QString& logMsg);
    
    // ========== Connection Status Signal ==========
    void connectionStatusChanged(const QString& status);

    // ========== TLS Log Buffer Signal ==========
    void tlsLogBufferChanged();

    // ========== Raw & Decrypted Packet Hex Signals ==========
    void rawPacketHexChanged();
    void decryptedPacketHexChanged();

    // ========== TLS HandShake Information Signals ==========
    void tlsVersionChanged(const QString& version);
    void tlsCipherChanged(const QString& cipher);
    void tlsKeyExchangeChanged(const QString& keyExchange);
    void tlsServerSigChanged(const QString& serverSig);
    void tlsServerPubKeyChanged(const QString& serverPubKey);

private:
    // Server Configuration
    QString _serverIpAddress = "192.168.0.203";
    QString _serverPortNumber = "4433";
    bool _serverConnected = false;
    
    // Routing Configuration
    QString _routingPortNumber = "14550";
    bool _routingConnected = false;
    
    // Credentials
    QString _caBundleFilePath = "";
    QString _clientCertFilePath = "";

    // ========== PQC TLS Context ==========
    pqc_tls_ctx_t* _pqcCtx = nullptr;
    QMutex _contextMutex;
    
    // ========== Read/Write Buffers ==========
    QByteArray _readBuffer;
    QByteArray _writeBuffer;
    
     // ========== Socket Notifiers ==========
     QSocketNotifier* _readNotifier = nullptr;
     QSocketNotifier* _writeNotifier = nullptr;
     
      // ========== TLS Log Buffer ==========
      QString _tlsLogBuffer;  // Latest 50 lines only
      
      // ========== Raw & Decrypted Packet Hex Buffers ==========
      QString _rawPacketHex;        // Latest 1 encrypted packet (hex string)
      QString _decryptedPacketHex;  // Latest 1 decrypted packet (hex string)

       // ========== TLS HandShake Information ==========
        QString _tlsVersion;
        QString _tlsCipher;
        QString _tlsKeyExchange;
        QString _tlsServerSig;
        QString _tlsServerPubKey;
     
      // ========== Worker Thread ==========
     PQCTLSConnectionWorker* _connectionWorker = nullptr;
     bool _isConnecting = false;

        // ========== Helper Methods ==========
        QString getPrivateFolderPath() const;
        void setupSocketNotifiers();
        void cleanupSocketNotifiers();
        void appendTlsLog(const QString& msg);  // Append log to buffer with timestamp
         void appendRawPacket(const uint8_t* data, int len);        // Capture encrypted packet
         void appendDecryptedPacket(const uint8_t* data, int len);  // Capture decrypted packet
         static QString bytesToHex(const uint8_t* data, int len);   // Convert bytes to hex string
         void extractAndLogHandshakeInfo(pqc_tls_ctx_t* ctx);       // Extract TLS handshake info

    // ========== Private Slots ==========
private slots:
    void onSocketReadyRead();
    void onSocketReadyWrite();

    // ========== JNI Callback Registration ==========
private:
    void registerJNICallback();
};
