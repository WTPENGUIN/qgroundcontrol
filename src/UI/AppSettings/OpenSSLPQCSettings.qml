/****************************************************************************
 *
 * (c) 2009-2020 QGROUNDCONTROL PROJECT <http://www.qgroundcontrol.org>
 *
 * QGroundControl is licensed according to the terms in the file
 * COPYING.md in the root of the source code directory.
 *
 ****************************************************************************/

import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import Qt.labs.platform as Labs
import QtCore

import QGroundControl
import QGroundControl.Controls
import QGroundControl.ScreenTools
import QGroundControl.Palette
import OpenSSLPQCSettings

Item {
    id: __openSSLPQCRoot
    anchors.fill: parent

    // State properties for credential management
    property bool caBundleSelected: false
    property bool clientCertSelected: false
    property bool isConnected: false
    property bool isRoutingConnected: false
    property bool isReadyToConnect: caBundleSelected && clientCertSelected

    // File names for display
    property string caBundleFileName: ""
    property string clientCertFileName: ""

    // Server configuration
    property string ipAddress: ""
    property string portNumber: ""
    property string routingPortNumber: ""

    // Message viewer content
    property string sslLogViewerContent: qsTr("Awaiting SSL logs...")
    property string rawPacketViewerContent: qsTr("Awaiting raw packets...")
    property string decryptedPacketViewerContent: qsTr("Awaiting decrypted packets...")
    property string mavlinkViewerContent: qsTr("Awaiting Mavlink messages...")

    // Download 폴더 경로 (Qt StandardPaths API)
    property string downloadFolder: StandardPaths.writableLocation(StandardPaths.DownloadLocation)

    QGCPalette {
        id: qgcPal
        colorGroupEnabled: true
    }

    // Helper function to extract filename from full path
    function getFileName(path) {
        if (!path || path === "") return ""
        return path.split('/').pop()
    }

    Component.onCompleted: {
        // C++ Singleton에서 값 읽어오기
        ipAddress = OpenSSLPQCSettings.serverIpAddress || "192.168.0.203"
        portNumber = OpenSSLPQCSettings.serverPortNumber || "4433"
        routingPortNumber = OpenSSLPQCSettings.routingPortNumber || "14550"
        isConnected = OpenSSLPQCSettings.serverConnected
        isRoutingConnected = OpenSSLPQCSettings.routingConnected
        
        // SSL 로그 버퍼 로드
        sslLogViewerContent = OpenSSLPQCSettings.tlsLogBuffer
        
        // 파일 선택 여부 판단
        caBundleSelected = (OpenSSLPQCSettings.caBundleFilePath !== "")
        clientCertSelected = (OpenSSLPQCSettings.clientCertFilePath !== "")
    }

    Connections {
        target: OpenSSLPQCSettings
    
        function onServerConnectedChanged(connected) {
            isConnected = connected
        }
    
        function onRoutingConnectedChanged(connected) {
            isRoutingConnected = connected
        }
        
        function onTlsLogBufferChanged() {
            sslLogViewerContent = OpenSSLPQCSettings.tlsLogBuffer
        }
    }

    QGCFlickable {
        anchors.fill: parent
        contentHeight: settingsColumn.height
        contentWidth: settingsColumn.width
        flickableDirection: Flickable.VerticalFlick

        ColumnLayout {
            id: settingsColumn
            width: __openSSLPQCRoot.width - (ScreenTools.defaultFontPixelWidth * 2 * 2)
            spacing: ScreenTools.defaultFontPixelHeight * 0.5

            // ===== Section 1: Credential Management =====
            SettingsGroupLayout {
                Layout.fillWidth: true
                heading: qsTr("Credential Management (CA/CRT)")

                RowLayout {
                    Layout.fillWidth: true
                    spacing: ScreenTools.defaultFontPixelWidth

                    // CA Bundle Column
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: 3

                        QGCButton {
                            Layout.fillWidth: true
                            text: qsTr("CA Bundle")
                            primary: caBundleSelected
                            onClicked: {
                                OpenSSLPQCSettings.callOpenPQCFileImportDialog("ca_bundle.crt")
                                caBundleSelected = true
                            }
                        }

                        QGCLabel {
                            Layout.alignment: Qt.AlignHCenter
                            text: getFileName(OpenSSLPQCSettings.caBundleFilePath) ? "(" + getFileName(OpenSSLPQCSettings.caBundleFilePath) + ")" : ""
                            font.pointSize: ScreenTools.smallFontPointSize
                            visible: getFileName(OpenSSLPQCSettings.caBundleFilePath) !== ""
                        }
                    }

                    // Client Certificate Column
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: 3

                        QGCButton {
                            Layout.fillWidth: true
                            text: qsTr("Client Certificate")
                            primary: clientCertSelected
                            onClicked: {
                                OpenSSLPQCSettings.callOpenPQCFileImportDialog("client_cert.crt")
                                clientCertSelected = true
                            }
                        }

                        QGCLabel {
                            Layout.alignment: Qt.AlignHCenter
                            text: getFileName(OpenSSLPQCSettings.clientCertFilePath) ? "(" + getFileName(OpenSSLPQCSettings.clientCertFilePath) + ")" : ""
                            font.pointSize: ScreenTools.smallFontPointSize
                            visible: getFileName(OpenSSLPQCSettings.clientCertFilePath) !== ""
                        }
                    }
                }
            }

            // ===== Section 2: Server Configuration =====
            SettingsGroupLayout {
                Layout.fillWidth: true
                heading: qsTr("Server Configuration")

                RowLayout {
                    Layout.fillWidth: true
                    spacing: ScreenTools.defaultFontPixelWidth

                    // IP Address TextField
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 3

                        QGCLabel {
                            text: qsTr("IP Address")
                            font.pointSize: ScreenTools.smallFontPointSize
                        }

                        QGCTextField {
                            Layout.fillWidth: true
                            text: ipAddress
                            onTextChanged: {
                                ipAddress = text
                                OpenSSLPQCSettings.serverIpAddress = text
                            }
                            placeholderText: qsTr("192.168.0.203")
                        }
                    }

                    // Port Number TextField
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 3

                        QGCLabel {
                            text: qsTr("Port")
                            font.pointSize: ScreenTools.smallFontPointSize
                        }

                        QGCTextField {
                            Layout.fillWidth: true
                            text: portNumber
                            onTextChanged: { 
                                portNumber = text
                                OpenSSLPQCSettings.serverPortNumber = text
                            }
                            placeholderText: qsTr("4433")
                            numericValuesOnly: true
                        }
                    }

                    // Connect Button Column
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 3

                        QGCButton {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 150
                            Layout.maximumWidth: 150
                            text: isConnected ? qsTr("Disconnect") : qsTr("Connect")
                            primary: isConnected
                            enabled: isReadyToConnect || isConnected
                            showBorder: true
                            onClicked: {
                                // Update C++ properties
                                OpenSSLPQCSettings.serverIpAddress = ipAddress
                                OpenSSLPQCSettings.serverPortNumber = portNumber
                                
                                // Call C++ methods
                                if (isConnected) {
                                    OpenSSLPQCSettings.disconnectFromServer()
                                    isConnected = false
                                } else {
                                    OpenSSLPQCSettings.connectToServer()
                                    isConnected = true
                                }
                            }
                        }
                    }
                }
            }

            // ===== Section 3: Routing Configuration =====
            SettingsGroupLayout {
                Layout.fillWidth: true
                heading: qsTr("Routing Configuration(Only Local UDP)")

                RowLayout {
                    Layout.fillWidth: true
                    spacing: ScreenTools.defaultFontPixelWidth

                    // Port Number TextField
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: 3

                        QGCLabel {
                            text: qsTr("Port")
                            font.pointSize: ScreenTools.smallFontPointSize
                        }

                        QGCTextField {
                            Layout.fillWidth: true
                            text: routingPortNumber
                            onTextChanged: {
                                routingPortNumber = text
                                OpenSSLPQCSettings.routingPortNumber = text
                            }
                            placeholderText: qsTr("14550")
                            numericValuesOnly: true
                        }
                    }

                    // Route/Disconnect Button Column
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: 3

                        QGCButton {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 150
                            Layout.maximumWidth: 150
                            text: isRoutingConnected ? qsTr("Disconnect") : qsTr("Route")
                            primary: isRoutingConnected
                            enabled: true
                            showBorder: true
                            onClicked: {
                                // Update C++ properties first
                                OpenSSLPQCSettings.routingPortNumber = routingPortNumber
                                
                                // Call C++ methods
                                if (isRoutingConnected) {
                                    OpenSSLPQCSettings.disconnectRouting()
                                    isRoutingConnected = false
                                } else {
                                    OpenSSLPQCSettings.routeConnection()
                                    isRoutingConnected = true
                                }
                            }
                        }
                    }
                }
            }

            // ===== Section 4: SSL Log Viewer =====
            SettingsGroupLayout {
                Layout.fillWidth: true
                heading: qsTr("SSL Log Viewer")

                Rectangle {
                    Layout.fillWidth: true
                    height: 180
                    color: qgcPal.windowShade
                    border.color: qgcPal.windowShadeDark
                    border.width: 1
                    radius: 4

                    QGCFlickable {
                        anchors.fill: parent
                        anchors.margins: 5
                        contentHeight: logText.implicitHeight

                        QGCLabel {
                            id: logText
                            width: parent.width
                            text: sslLogViewerContent
                            wrapMode: Text.Wrap
                            font.family: "Courier New"
                            font.pointSize: ScreenTools.smallFontPointSize
                        }
                    }
                }
            }

            // ===== Section 5: Message Viewers =====
            SettingsGroupLayout {
                Layout.fillWidth: true
                heading: qsTr("Message Viewers")

                RowLayout {
                    Layout.fillWidth: true
                    spacing: ScreenTools.defaultFontPixelWidth

                    // Raw Packet Viewer
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: 3

                        QGCLabel {
                            text: qsTr("Raw Packet")
                            font.pointSize: ScreenTools.smallFontPointSize
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 250
                            color: qgcPal.windowShade
                            border.color: qgcPal.windowShadeDark
                            border.width: 1
                            radius: 4

                            QGCFlickable {
                                anchors.fill: parent
                                anchors.margins: 5
                                contentHeight: rawPacketText.implicitHeight

                                QGCLabel {
                                    id: rawPacketText
                                    width: parent.width
                                    text: rawPacketViewerContent
                                    wrapMode: Text.Wrap
                                    font.family: "Courier New"
                                    font.pointSize: ScreenTools.smallFontPointSize
                                }
                            }
                        }
                    }

                    // Decrypted Packet Viewer
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: 3

                        QGCLabel {
                            text: qsTr("Decrypted Packet")
                            font.pointSize: ScreenTools.smallFontPointSize
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 250
                            color: qgcPal.windowShade
                            border.color: qgcPal.windowShadeDark
                            border.width: 1
                            radius: 4

                            QGCFlickable {
                                anchors.fill: parent
                                anchors.margins: 5
                                contentHeight: decryptedPacketText.implicitHeight

                                QGCLabel {
                                    id: decryptedPacketText
                                    width: parent.width
                                    text: decryptedPacketViewerContent
                                    wrapMode: Text.Wrap
                                    font.family: "Courier New"
                                    font.pointSize: ScreenTools.smallFontPointSize
                                }
                            }
                        }
                    }

                    // Mavlink Message Viewer
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        spacing: 3

                        QGCLabel {
                            text: qsTr("Mavlink Messages")
                            font.pointSize: ScreenTools.smallFontPointSize
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            height: 250
                            color: qgcPal.windowShade
                            border.color: qgcPal.windowShadeDark
                            border.width: 1
                            radius: 4

                            QGCFlickable {
                                anchors.fill: parent
                                anchors.margins: 5
                                contentHeight: mavlinkText.implicitHeight

                                QGCLabel {
                                    id: mavlinkText
                                    width: parent.width
                                    text: mavlinkViewerContent
                                    wrapMode: Text.Wrap
                                    font.family: "Courier New"
                                    font.pointSize: ScreenTools.smallFontPointSize
                                }
                            }
                        }
                    }
                }
            }

            // Spacer
            Item {
                Layout.fillHeight: true
            }
        }
    }
}
