# dataview-vlc-automator
Dataview controller for VLC

## Generating a X.509 Server Certificate

In order to provide secure communications between the RPC consumer and the RPC server, TLS is utilized. You must create a X.509 Server certificate for this to work.

<pre>
openssl genrsa -out server.pem 4096
openssl req -new -x509 -key server.pem -out cert.pem -days 730
</pre>

Once you have generated the private key and certificate, copy the certificate (cert.pem) to the machine the RPC consumer is operating from.