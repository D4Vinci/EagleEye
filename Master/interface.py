import webbrowser, logging
from threats import *
from flask import Flask, render_template, request, jsonify
# from flask_ngrok import run_with_ngrok
from functools import wraps
from datetime import datetime

global rows, row_id, devices
app = Flask(__name__, static_url_path=None, static_folder="assets")
# run_with_ngrok(app)
row_id = 0
rows = {
	"data":[]
}
devices = {
	"ips":[],
	"details":[],
}
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
host_port = 8000
current_host = "127.0.0.1"
serve_localhost = True
view_browser = True

if not serve_localhost:
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.connect(("8.8.8.8", 80))
	current_host = sock.getsockname()[0]
	sock.close()

def savePacket(user_ip, json_data):
	global rows, row_id, devices
	for d in devices["details"]:
		if d["device_ip"]==user_ip:
			d["Status"] = "Active"
			break
	row = {
		"id": row_id,
		"ip":user_ip,
		"time":json_data.get("createdAt","0"),
		"srcmac":json_data.get("ethernetSrcMac",""),
		"dstmac":json_data.get("ethernetDstMac",""),
		"ethernet_type":json_data.get("ethernetType",""),
		"dns_query":json_data.get("dnsQuery",""),
		"srcip":json_data.get("IPv4SrcIP","-"),
		"dstip":json_data.get("IPv4DstIP","-"),
		"ip_proto":json_data.get("IPv4Protocol",""),
		"tcp_srcport":json_data.get("TCPSrcPort",""),
		"tcp_dstport":json_data.get("TCPDstPort",""),
		"tcp_seq":json_data.get("TCPSeq",""),
		"udp_srcport":json_data.get("UDPSrcPort",""),
		"udp_dstport":json_data.get("UDPDstPort",""),
		"udp_length":json_data.get("UDPLength",""),
		"ICMPType":json_data.get("ICMPType",""),
		"ICMPSeq":json_data.get("ICMPSeq",""),
		"ICMPChecksum":json_data.get("ICMPChecksum",""),
		"payload":json_data.get("Payload","").strip(),
		"app_layer": '<span class="text-danger">NO</span>'
	}
	row = {k: v for k, v in row.items() if v!=""}
	protocols = json_data.get("PacketLayers",[""])
	if "Payload" in protocols:
		row["app_layer"] = '<span class="text-success">YES</span>'
		protocols.remove("Payload")
	row["protocols"] = ", ".join(protocols)
	# row["payload"] = row["payload"].encode()
	row_id +=1
	rows["data"].append(row)

def addUser(user_ip, json_data):
	global devices
	if user_ip not in devices["ips"]:
		devices["ips"].append(user_ip)
		devices["details"].append({
			"Status": "Active",
			"device_ip":user_ip,
			"Devices_name":json_data["DeviceName"],
			"User_name":json_data["Username"],
			"OS":json_data["OS"]
		})
	else:
		for d in devices["details"]:
			if d["device_ip"]==user_ip:
				d["Status"] = "Active"
				break

def log_this_one():
	def hooker(func): # Yes hooker :"D from hook
		@wraps(func)
		def func_returner(*args, **kwargs):
			proto = request.environ.get('SERVER_PROTOCOL')
			method = request.method
			current_endpoint = str(request.url_rule)
			current_time     = datetime.utcnow()
			if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
				user_ip = request.environ['REMOTE_ADDR']
			else:
				user_ip = request.environ['HTTP_X_FORWARDED_FOR']
			print(f'{user_ip} {R}- -{end} [{current_time}] "{method} {current_endpoint} {proto}" ')
			if request.is_json:
				json_data = request.get_json()
				# print(json.dumps(json_data, sort_keys=True, indent=2))
				if json_data["RequestType"]=="packet":
					savePacket(json_data["Deviceip"], json_data["Data"])
				else:
					# print(json.dumps(json_data, sort_keys=True, indent=2))
					addUser(json_data["Deviceip"], json_data)
			return func(*args, **kwargs)
		return func_returner
	return hooker

@app.route('/results_table', methods=["GET"])
def get_table():
	# print(rows)
	# return rows
	return jsonify({ "data":sorted(rows["data"], key = lambda i: i['time'], reverse=True) })

@app.route('/devices_list', methods=["GET"])
def get_devices():
	# print(rows)
	return jsonify(devices["details"])

@app.route('/threats_list', methods=["GET"])
def get_threats():
	check = threats_checker(rows["data"])
	result = check.launch()
	if result:
		return jsonify(result)
	else:
		return jsonify([])

@app.route('/', methods=["GET", "POST"])
@log_this_one()
def hello():
	return render_template("index.html")
	# return "Running in console :)"

@app.route('/exit', methods=["GET"])
def goodbye():
	os._exit(0)
	return "Bye!"

@app.after_request
def add_header(r):
	"""
	Add headers to both force latest IE rendering engine or Chrome Frame,
	and also to cache the rendered page for 10 minutes.
	"""
	r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
	r.headers["Pragma"] = "no-cache"
	r.headers["Expires"] = "0"
	r.headers['Cache-Control'] = 'public, max-age=0'
	#if r.headers["Content-Type"] !="application/json" and r.status_code!=304:
	#    print(str(r.status_code)+" -",end="")
	return r

def open_browser():
	time.sleep(2)
	# browser = webbrowser.get()
	webbrowser.open(f'http://{current_host}:{host_port}/',new=0)

if __name__ == '__main__':
	if view_browser:
		threading.Thread(target=open_browser,daemon=True).start()
	print(f'Serving on url http://{current_host}:{host_port}/')
	while True:
		try:
			app.run(host=current_host, port=host_port, threaded=True, debug=True, use_reloader=False)
			# app.run()
			break
		except OSError:
			sys.stdout.write(f"[!] Port {host_port} is in use! Trying the following port")
			sys.stdout.flush()
			host_port +=1
			continue
