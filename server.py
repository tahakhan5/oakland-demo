from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import os

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        user_html = self.client_address[0].replace(".","").replace(":","")+".html"
        self.path = self.path.split("?")[0]
        
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
        
        if user_html in files:
    		    
            if self.path == "/":
                self.path = self.path+user_html

            sendReply = False

            if self.path.endswith(".html"):
                mimetype='text/html'
                sendReply = True
            if self.path.endswith(".jpg"):
                mimetype='image/jpg'
                sendReply = True
            if self.path.endswith(".gif"):
                mimetype='image/gif'
                sendReply = True
            if self.path.endswith(".js"):
                mimetype='application/javascript'
                sendReply = True
            if self.path.endswith(".css"):
                mimetype='text/css'
                sendReply = True

            if sendReply == True:
                #Open the static file requested and send it
                f = open(self.path[1:]) 
                self.send_response(200)
                self.send_header('Content-type',mimetype)
                self.end_headers()
                self.wfile.write(f.read())
                f.close()
        else:
            self.send_error(404,'Please try again with signed in with your google account')
        return




class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""    
if __name__ == '__main__':

    abs_path =  os.path.abspath(".")
    os.chdir(abs_path+"/client_files/")

    server = ThreadedHTTPServer(('', 8000), Handler)
    print 'Starting server, use <Ctrl-C> to stop'
    server.serve_forever()
