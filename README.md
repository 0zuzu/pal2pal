# Pal2Pal
Pal2Pal is a cross-platform app for peer-to-peer file sharing and messaging. It's similar in spirit to Discord, but connections are made directly between devices instead of going through a central server.

Because transfers happen device-to-device, there's no imposed limit on file size or bandwidth. And because there's no central server relaying messages and files, it's also more privacy conscious.

What's a "Pal"?

A Pal is another peer you're connected to — a friend, collaborator or one of your devices. Anyone you chat or share files with. You add a Pal by sharing a link or a QR code; whoever opens it connects to you directly.

Features
Direct, peer-to-peer messaging
File sharing with no size or bandwidth limit
Adding Pals via link or QR code
Cross-platform: Windows, macOS, Linux

Pal2Pal uses libp2p for the networking layer — discovering and connecting to peers, including handling cases like both sides being behind home routers (NAT traversal). Once two devices are connected, messages and files are sent directly between them rather than through a server.

The interface is planned to be built with Wails, which allows a native desktop app using web technologies for the UI, without bundling a full browser.
