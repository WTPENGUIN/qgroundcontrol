/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#pragma once

#include <QtCore/QThread>
#include <QtCore/QByteArray>
#include <QtCore/QMutex>
#include <sys/socket.h>
#include <netinet/in.h>

class OpenSSLPQCController;

/// UDP Routing Worker for Local MAVLink Bridging
/// Location: src/Comms/PqcTls/UDPRoutingWorker.h
/// 
/// Purpose:
/// Manages UDP socket for local MAVLink routing on 127.0.0.1.
/// Runs in separate worker thread to avoid blocking main thread.
/// Forwards data between local UDP clients and PQC TLS encrypted channel.
/// 
/// Design:
/// - Binds to 127.0.0.1 (localhost only, security)
/// - Single UDP socket with stateless client tracking
/// - No logging/errors when TLS connection fails (silent operation)
/// - Stateful: last active client address stored for response routing
/// 
/// Data Flow:
/// Client (UDP) → UDPRoutingWorker (receive) 
///              → OpenSSLPQCController (forward to TLS)
///              → Remote Server (TLS encrypted)
/// 
/// Remote Server → OpenSSLPQCController (TLS decrypt)
///              → UDPRoutingWorker (forward)
///              → Client (UDP response)

class UDPRoutingWorker : public QThread
{
    Q_OBJECT
    
public:
    /// Constructor
    /// @param parent OpenSSLPQCController instance
    explicit UDPRoutingWorker(OpenSSLPQCController* parent);
    
    /// Destructor - cleans up socket
    ~UDPRoutingWorker();
    
    /// Main worker thread execution (blocking operations OK here)
    void run() override;
    
    /// Forward data received from server to last active local client
    /// Called from main thread by OpenSSLPQCController
    /// Thread-safe via mutex
    /// @param data Decrypted MAVLink frame to send to client
    void forwardDataToClient(const QByteArray& data);
    
    /// Set UDP routing port (must be called before run())
    /// @param port UDP port number (e.g., 18000)
    void setRoutingPort(int port);
    
    /// Request worker thread to stop gracefully
    /// Called from main thread during shutdown
    void requestStop();
    
signals:
    /// Emitted when data received from local client
    /// Connected to OpenSSLPQCController::onRoutingDataReceived
    /// @param data Raw MAVLink frame from local client
    void dataReceived(const QByteArray& data);
    
    /// Emitted when routing socket status changes
    /// Connected to OpenSSLPQCController::onRoutingStatusChanged
    /// @param connected true=socket ready, false=socket error/closed
    void statusChanged(bool connected);
    
private:
    // ========== Member Variables ==========
    
    OpenSSLPQCController* _parent;
    int _routingPort = 18000;               ///< UDP port (default 18000)
    int _udpSocket = -1;                    ///< UDP socket file descriptor
    bool _running = false;                  ///< Worker thread state
    bool _stopRequested = false;            ///< Graceful shutdown flag
    
    /// Last active client address (used for response routing)
    /// Protected by _routingMutex
    sockaddr_storage _lastClientAddr;
    socklen_t _lastClientAddrLen = 0;
    
    /// Mutex for thread-safe access to _lastClientAddr
    QMutex _routingMutex;
    
    /// Read buffer for incoming UDP packets
    /// Conservative size: 8KB (2x typical MAVLink frame)
    static constexpr int READ_BUFFER_SIZE = 8192;
    QByteArray _readBuffer;
    
    /// Write buffer for outgoing UDP responses
    static constexpr int WRITE_BUFFER_SIZE = 8192;
    QByteArray _sendBuffer;
    
    // ========== Private Methods ==========
    
    /// Initialize UDP socket and bind to 127.0.0.1:_routingPort
    /// @return true on success, false on failure
    bool initializeSocket();
    
    /// Close and cleanup UDP socket
    /// Called in destructor or on error
    void cleanupSocket();
};
