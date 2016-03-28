#!/usr/bin/env python3
import sys
assert sys.version >= '3.3', 'Please use Python 3.3 or higher.'

import argparse
import os
import ssl
import json
from threading import Event, Thread, Timer

import asyncio
import aiohttp
import aiohttp.server

from urllib.parse import urlparse, parse_qsl
from aiohttp.multidict import MultiDict


def constant_time_equals(val1, val2):
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0

import vlc


class MonitorThread(Thread):
    def __init__(self, event, vlc_controller):
        Thread.__init__(self)
        self.stopped = event
        self.vlc_controller = vlc_controller

    def run(self):
        while not self.stopped.wait(5):
            self.vlc_controller.timer_callbacks()


class DataviewVLCController(object):
    def __init__(self):
      self.instance = vlc.Instance()
      self.mp = self.instance.media_player_new()
      self.ml = self.instance.media_list_new()
      self.mlp = self.instance.media_list_player_new()
      self.mlp.set_media_player(self.mp)
      self.mlp.set_media_list(self.ml)
      self.volume = 50
      self.mp.audio_set_volume(self.volume)
      self.monitor_stop_flag = Event()
      self.monitor = MonitorThread(self.monitor_stop_flag, self)
      self.url = None
      self.previously_played = []

    def start_timers(self):
        if not self.monitor.is_alive() and not self.monitor_stop_flag.is_set():
            self.monitor.start()

    def stop_timers(self):
        self.monitor_stop_flag.set()

    def timer_callbacks(self):
        self.resume_playing()
        self.update_previous()

    def resume_playing(self):
        """
        Resume playing if the source dropped
        @return:
        """
        if not self.mp.get_media():
           self.play(self.url)

    def update_previous(self):
        if len(self.previously_played) >= 10:
            del self.previously_layed[0]

        current = self.get_playback_details()
        if len(self.previously_played) == 0 or current != self.previously_played[-1]:
            if current['song']:
                self.previously_played.append(current)

    def pause(self):
      """
      Pause the audio stream.
      """
      self.mp.set_pause(1)
      return True

    def unpause(self):
      """
      Unpause the audio stream.
      """
      self.mp.set_pause(0)
      return True

    def set_volume(self, volume):
      """
      Sets the volume for the current player instance
      """
      self.volume = int(volume)
      self.mp.audio_set_volume(self.volume)

      return True

    def play(self, url):
      self.url = url
      m = vlc.Media(url)

      if self.mp.get_media() is None or self.mp.get_media().get_mrl() != m.get_mrl():
          self.ml.add_media(m)
          self.mlp.play_item(m)
          self.mp.audio_set_volume(self.volume)

      self.start_timers()

      # hack to set the default volume
      while True:
          if self.mp.audio_get_volume() is not -1:
              self.mp.audio_set_volume(self.volume)
              return True

    def mute(self):
      self.mp.audio_set_mute(True)
      return True

    def unmute(self):
      self.mp.audio_set_mute(False)
      return True

    def get_playback_information(self):
        return {'current': self.get_playback_details(),
                'previous': self.previously_played[:-1]}

    def get_playback_details(self):
         m = self.mp.get_media()
         if m is None:
             return {}

         return {'genre': m.get_meta(vlc.Meta.Genre),
                 'title': m.get_meta(vlc.Meta.Title),
                 'song': m.get_meta(vlc.Meta.NowPlaying)}


    def _send_to_server(command):
      pass


class DataviewRPCServer(aiohttp.server.ServerHttpProtocol):
    def __init__(self, dispatch_functions, auth_token):
        self.dispatch_functions = dispatch_functions
        self.auth_token = auth_token
        if len(auth_token) < 32:
            raise Exception("auth_token is insufficently long")
        super().__init__()

    @asyncio.coroutine
    def handle_request(self, message, payload):
        print('method = {!r}; path = {!r}; version = {!r}'.format(
        message.method, message.path, message.version))

        if message.method == 'POST' and message.path == '/rpc':
            if not 'Authorization' in message.headers:
                response = aiohttp.Response(
                    self.writer, 401, http_version=message.version
                )
                response.add_header('Content-Length', '0')
                response.add_header('WWW-Authenticate', 'Token')
                response.send_headers()
                return

            authorization = message.headers.get('Authorization').split(' ')
            if authorization[0] != 'Token' or not constant_time_equals(authorization[1], self.auth_token):
                response = aiohttp.Response(
                    self.writer, 403, http_version=message.version
                )
                response.add_header('Content-Length', '0')
                response.send_headers()
                return

            # authorization passed, process the request.
            data = yield from payload.read()
            response = aiohttp.Response(
                self.writer, 200, http_version=message.version
            )
            result = self.process_request(data)
            response.add_header('Content-Length', str(len(result)))
            response.send_headers()

            response.write(result)
        else:
            response = aiohttp.Response(
                self.writer, 405, http_version=message.version
            )
            response.add_header('Accept', 'POST')
            response.send_headers()

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport
        super().connection_made(transport)

    def process_request(self, data):
        response = {}
        message = data.decode()
        
        try:
            payload = json.loads(message)
        except Exception:
            response = {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}
            return str.encode(json.dumps(response) + "\n")

        try:
            if payload['jsonrpc'] != '2.0':
                response = {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}
                return str.encode(json.dumps(response) + "\n")
            response['jsonrpc'] = '2.0'
            response['id'] = payload['id']
        except Exception:
            pass

        if payload['method'] not in self.dispatch_functions:
              response = {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": payload['id']},
              return str.encode(json.dumps(response) + "\n")
        #try:
        if type(payload['params']) is dict:
            response['result'] = self.dispatch_functions[payload['method']](**payload['params'])
        else:
            response['result'] = self.dispatch_functions[payload['method']](*payload['params'])

        #except Exception as e:
        #    print(e)
        #    pass

        return str.encode(json.dumps(response) + "\n")

ARGS = argparse.ArgumentParser(description="Run simple http server.")
ARGS.add_argument(
    '--host', action="store", dest='host',
    default='localhost', help='Host name')
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

    if sys.version >= '3.4':
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    else:
        sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

    sslcontext.load_cert_chain(args.certfile, args.keyfile)

    loop = asyncio.get_event_loop()
    c = DataviewVLCController();
    f = loop.create_server(
        lambda: DataviewRPCServer(
          {'pause': lambda: c.pause(),
            'unpause': lambda: c.unpause(),
            'play': lambda url: c.play(url),
            'set_volume': lambda volume: c.set_volume(volume),
            'mute': lambda: c.mute(),
            'unmute': lambda: c.unmute(),
            'get_playback_information': lambda: c.get_playback_information(),
          }, os.environ.get('RPCSERVER_TOKEN')
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
