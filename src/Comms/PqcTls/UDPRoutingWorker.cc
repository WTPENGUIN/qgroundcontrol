/****************************************************************************
 *
 * (c) 2009-2024 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

#include "UDPRoutingWorker.h"
#include "OpenSSLPQCController.h"
#include "QGCLoggingCategory.h"

#include <QtCore/QThread>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#ifdef Q_OS_WIN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

Q_DECLARE_LOGGING_CATEGORY(OpenSSLPQCControllerLog)

// ========== Constructor / Destructor ==========

UDPRoutingWorker::UDPRoutingWorker(OpenSSLPQCController* parent)
    : QThread(parent), _parent(parent), _udpSocket(-1), _running(false), _stopRequested(false)
{
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] Constructor: UDP Routing worker created";
    
    // Initialize buffer sizes
    _readBuffer.reserve(READ_BUFFER_SIZE);
    _sendBuffer.reserve(WRITE_BUFFER_SIZE);
}

UDPRoutingWorker::~UDPRoutingWorker()
{
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] Destructor: Cleaning up UDP routing worker";
    
    // Stop thread if running
    if (isRunning()) {
        requestStop();
        wait(5000);
    }
    
    // Cleanup socket
    cleanupSocket();
    
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] Destructor: UDP routing worker destroyed";
}

// ========== Public Methods ==========

void UDPRoutingWorker::setRoutingPort(int port)
{
    if (port > 0 && port < 65536) {
        _routingPort = port;
        qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] Routing port set to" << port;
    } else {
        qCWarning(OpenSSLPQCControllerLog) << "[UDPRouter] Invalid port:" << port;
    }
}

void UDPRoutingWorker::requestStop()
{
    _stopRequested = true;
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] Stop requested";
}

void UDPRoutingWorker::forwardDataToClient(const QByteArray& data)
{
    if (data.isEmpty()) {
        return;
    }
    
    // Lock for thread-safe access to client address
    QMutexLocker locker(&_routingMutex);
    
    // Check if we have a valid client address
    if (_lastClientAddrLen == 0) {
        // No client connected yet, silently discard
        return;
    }
    
    // Check socket validity
    if (_udpSocket < 0) {
        // Socket not initialized, silently discard
        return;
    }
    
    // Send data to last active client
    ssize_t bytesSent = sendto(
        _udpSocket,
        data.data(),
        static_cast<size_t>(data.size()),
        0,
        reinterpret_cast<struct sockaddr*>(&_lastClientAddr),
        _lastClientAddrLen
    );
    
    if (bytesSent < 0) {
        // Silent failure - no logging as per requirement
        // Socket remains valid for next attempt
    }
    
    // Note: No logging on error (requirement: silent operation when TLS disconnects)
}

// ========== Worker Thread Execution ==========

void UDPRoutingWorker::run()
{
    qCDebug(OpenSSLPQCControllerLog) << "";
    qCDebug(OpenSSLPQCControllerLog) << "========== UDP ROUTING WORKER STARTED ==========";
    qCDebug(OpenSSLPQCControllerLog) << "Thread ID:" << QThread::currentThreadId();
    qCDebug(OpenSSLPQCControllerLog) << "Binding to 127.0.0.1:" << _routingPort;
    qCDebug(OpenSSLPQCControllerLog) << "============================================";
    qCDebug(OpenSSLPQCControllerLog) << "";
    
    // Initialize UDP socket
    if (!initializeSocket()) {
        qCCritical(OpenSSLPQCControllerLog) << "[UDPRouter] Failed to initialize socket";
        emit statusChanged(false);
        return;
    }
    
    _running = true;
    emit statusChanged(true);
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] UDP socket ready for routing";
    
    // Main event loop
    while (!_stopRequested && _running) {
        // Prepare to receive
        _readBuffer.clear();
        _readBuffer.resize(READ_BUFFER_SIZE);
        
        // Prepare client address storage
        sockaddr_storage clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        
        // Blocking recvfrom - wait for UDP packet
        ssize_t bytesReceived = recvfrom(
            _udpSocket,
            _readBuffer.data(),
            static_cast<size_t>(READ_BUFFER_SIZE),
            0,
            reinterpret_cast<struct sockaddr*>(&clientAddr),
            &clientAddrLen
        );
        
        // Check for errors or shutdown
        if (_stopRequested) {
            break;
        }
        
        if (bytesReceived < 0) {
            // Socket error - continue waiting silently
            // (could be EINTR, EAGAIN, etc.)
            #ifdef Q_OS_WIN
                if (WSAGetLastError() == WSAEINTR) {
                    continue;
                }
            #else
                if (errno == EINTR) {
                    continue;
                }
            #endif
            // Other errors: continue silently (no logging)
            msleep(10);
            continue;
        }
        
        if (bytesReceived == 0) {
            // No data - continue waiting
            msleep(10);
            continue;
        }
        
        // Data received - update client address and emit signal
        {
            QMutexLocker locker(&_routingMutex);
            memcpy(&_lastClientAddr, &clientAddr, clientAddrLen);
            _lastClientAddrLen = clientAddrLen;
        }
        
        // Trim buffer to actual received size
        _readBuffer.resize(static_cast<int>(bytesReceived));
        
        // Emit signal to main thread for processing
        emit dataReceived(_readBuffer);
    }
    
    // Cleanup on exit
    cleanupSocket();
    _running = false;
    emit statusChanged(false);
    
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] UDP routing worker exiting";
}

// ========== Private Methods ==========

bool UDPRoutingWorker::initializeSocket()
{
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] Initializing UDP socket...";
    
    // Create UDP socket
    _udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (_udpSocket < 0) {
        qCCritical(OpenSSLPQCControllerLog) << "[UDPRouter] Failed to create UDP socket";
        return false;
    }
    
    // Set socket options
    int optval = 1;
    
    // Allow address reuse (SO_REUSEADDR)
    if (setsockopt(_udpSocket, SOL_SOCKET, SO_REUSEADDR, 
                   reinterpret_cast<const char*>(&optval), sizeof(optval)) < 0) {
        qCWarning(OpenSSLPQCControllerLog) << "[UDPRouter] Failed to set SO_REUSEADDR";
    }
    
    // Non-blocking mode (for graceful shutdown)
    #ifdef Q_OS_WIN
        unsigned long mode = 1;
        if (ioctlsocket(_udpSocket, FIONBIO, &mode) != NO_ERROR) {
            qCWarning(OpenSSLPQCControllerLog) << "[UDPRouter] Failed to set non-blocking mode";
        }
    #else
        int flags = fcntl(_udpSocket, F_GETFL, 0);
        if (fcntl(_udpSocket, F_SETFL, flags | O_NONBLOCK) < 0) {
            qCWarning(OpenSSLPQCControllerLog) << "[UDPRouter] Failed to set non-blocking mode";
        }
    #endif
    
    // Bind to localhost:port
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(static_cast<uint16_t>(_routingPort));
    
    if (bind(_udpSocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0) {
        qCCritical(OpenSSLPQCControllerLog) << "[UDPRouter] Failed to bind socket to 127.0.0.1:" 
                                            << _routingPort;
        cleanupSocket();
        return false;
    }
    
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] ✅ UDP socket bound successfully";
    return true;
}

void UDPRoutingWorker::cleanupSocket()
{
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] Cleaning up UDP socket...";
    
    if (_udpSocket >= 0) {
        #ifdef Q_OS_WIN
            closesocket(_udpSocket);
        #else
            close(_udpSocket);
        #endif
        _udpSocket = -1;
    }
    
    // Clear client address
    {
        QMutexLocker locker(&_routingMutex);
        _lastClientAddrLen = 0;
    }
    
    qCDebug(OpenSSLPQCControllerLog) << "[UDPRouter] UDP socket cleaned up";
}
