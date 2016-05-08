from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import os


x =1


def run_response_server():

	global x

	class Handler(BaseHTTPRequestHandler):
	
		#Handler for the GET requests
		def do_GET(self):
			print x

			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			# Send the html message
			self.wfile.write("Hello World !")
			return


	class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
	    """Handle requests in a separate thread."""

	server = ThreadedHTTPServer(('', 8000), Handler)
	print 'Starting server, use <Ctrl-C> to stop'
	server.serve_forever()


run_response_server()

