# Dataview VLC Automator
This project includes a Dataview automator for VLC. This component is intended to be run on a separate machine and allows dataview to communicate with VLC securely.

## Generating a X.509 Server Certificate

In order to provide secure communications between the RPC consumer and the RPC server, TLS is utilized. You must create a X.509 Server certificate for this to work.

<pre>
openssl genrsa -out server.pem 4096
openssl req -new -x509 -key server.pem -out cert.pem -days 730
</pre>

Once you have generated the private key and certificate, copy the certificate (cert.pem) to the machine the RPC consumer is operating from.

## Generating Authentication Token

<pre>
$ openssl rand -hex 32
493152a14843198555759262f1bd767235789aebdcc5f1b1f8f2cd3a965c8c7a
</pre>

When you launch the automator script, be sure that the RPCSERVER_TOKEN environment variable is set.

<pre>
export RPCSERVER_TOKEN='GENERATED_TOKEN'
</pre>

## Launching automator

Be sure that you have generated the X.509 Server Certificate and exported the RPCSERVER_TOKEN environment variable, then:

<pre>
$ python3 automator.py --tlscert cert.pem --tlskey server.pem
</pre>
