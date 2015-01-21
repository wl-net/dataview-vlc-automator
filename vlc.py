#!/usr/bin/env python3
import sys
assert sys.version >= '3.3', 'Please use Python 3.3 or higher.'

import argparse
import logging
import os
import ssl
import json

import asyncio
import aiohttp
import aiohttp.server

class DataviewVLCController():
    def pause():
      """
      Pause the audio stream.
      NOTE: vlc's CLI interface only allows toggle of pause and is_playing does not consider pause state
      """
      command = "pause"
      return True
    
    def set_volume(volume):
      """
      Sets the volume for the current player instance
      """
      command = "volume {}".format(int(volume))
      
      return True
    
    def play(url):
      command = "enqueue {}".format(url)
    
    def mute():
      command = ""
      print("mute() called")
      return True
    
    def unmute():
      command = ""
      print("unmute() called")
      return True
    
    def _send_to_server(command):
      pass

class DataviewRPCServer(asyncio.Protocol):
    def __init__(self, dispatch_functions):
        self.dispatch_functions = dispatch_functions

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        response = {}
        message = data.decode()
        
        try:
            payload = json.loads(message)
        except Exception:
            response = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}
            self.transport.write(str.encode(json.dumps(response) + "\n"))
            return

        try:
            if payload['jsonrpc'] != '2.0':
                response = {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}
                self.transport.write(str.encode(json.dumps(response) + "\n"))
                return
            response['jsonrpc'] = '2.0'
            response['id'] = payload['id']
        except Exception:
            pass

        if payload['method'] not in self.dispatch_functions:
              response = {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": payload['id']},
              self.transport.write(str.encode(json.dumps(response) + "\n"))
              return
        #try:
        response['result'] = self.dispatch_functions[payload['method']](*payload['params'])
        #except Exception as e:
        #    print(e)
        #    pass
            
        
        print('Data received: {!r}'.format(message))

        print('Send: {!r}'.format(json.dumps(response)))
        self.transport.write(str.encode(json.dumps(response) + "\n"))

        print('Close the client socket')
        #self.transport.close()

ARGS = argparse.ArgumentParser(description="Run simple http server.")
ARGS.add_argument(
    '--host', action="store", dest='host',
    default='127.0.0.1', help='Host name')
ARGS.add_argument(
    '--port', action="store", dest='port',
    default=8080, type=int, help='Port number')
ARGS.add_argument(
    '--tlscert', action="store", dest='certfile', help='TLS X.509 certificate file.')
ARGS.add_argument(
    '--tlskey', action="store", dest='keyfile', help='TLS key file.')

def main():
    args = ARGS.parse_args()

    if ':' in args.host:
        args.host, port = args.host.split(':', 1)
        args.port = int(port)

    here = os.path.join(os.path.dirname(__file__), 'tests')

    sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23) # TODO python 3.4+ check
    sslcontext.load_cert_chain(args.certfile, args.keyfile)

    loop = asyncio.get_event_loop()
    f = loop.create_server(
        lambda: DataviewRPCServer(
          {'pause': lambda: DataviewVLCController.pause(),
            'set_volume': lambda volume: DataviewVLCController.set_volume(volume),
            'mute': lambda: DataviewVLCController.mute(),
            'unmute': lambda: DataviewVLCController.unmute()
          }
        ),
        args.host, args.port,
        ssl = sslcontext)
    svr = loop.run_until_complete(f)
    socks = svr.sockets
    print('Server started. Waiting for connections on ', socks[0].getsockname())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()