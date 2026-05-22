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
#if defined(Q_OS_ANDROID)
#include <QtCore/QJniObject>
#include "src/Android/AndroidInterface.h"
#endif

Q_DECLARE_LOGGING_CATEGORY(OpenSSLPQCLog)

/// OpenSSL PQC Settings - Singleton for QML/C++ integration
/// Location: src/Comms/PqcTls/OpenSSLPQCSettings.h
/// Purpose: UI state management and command invocation from QML
/// Note: This is a technology demonstration implementation with no dependency on existing communication links
class OpenSSLPQCSettings : public QObject
{
    Q_OBJECT

public:
    explicit OpenSSLPQCSettings(QObject *parent = nullptr);

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

    // ========== Getter Methods ==========
    QString serverIpAddress() const { return _serverIpAddress; }
    QString serverPortNumber() const { return _serverPortNumber; }
    bool serverConnected() const { return _serverConnected; }
    
    QString routingPortNumber() const { return _routingPortNumber; }
    bool routingConnected() const { return _routingConnected; }
    
    QString caBundleFilePath() const { return _caBundleFilePath; }
    QString clientCertFilePath() const { return _clientCertFilePath; }

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

signals:
    void serverIpAddressChanged(const QString& address);
    void serverPortNumberChanged(const QString& port);
    void serverConnectedChanged(bool connected);
    
    void routingPortNumberChanged(const QString& port);
    void routingConnectedChanged(bool connected);
    
    void caBundleFilePathChanged(const QString& path);
    void clientCertFilePathChanged(const QString& path);

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

    // ========== Helper Methods ==========
    QString getPrivateFolderPath() const;

    // ========== JNI Callback Registration ==========
    void registerJNICallback();
};
