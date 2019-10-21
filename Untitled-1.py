import socket
import json
import sys
import requests
from os.path import expanduser

home = expanduser("~")

api_token = '<insert_api_token_from_virustotal>'
api_url_base = 'https://www.virustotal.com/vtapi/v2/'

HOST = '0.0.0.0'
PORT = 5044

headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {0}'.format(api_token)}

def scan_file():

    api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_token}

    files = {'file': ('/Users/tome.kirov/Desktop/test.txt', open('/test.txt', 'rb'))}
    response = requests.post(api_url, files=files, params=params)

    return (response.json()['sha256'])

sha256var = scan_file()

def file_report():

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_token, 'resource': sha256var}

    response = json.dumps(requests.get(url, params=params).json())

    return(response)

file_report_response = file_report()

f = open( 'export.json', 'w' )
f.write( file_report_response ) 
f.close()


try:
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as msg:
  sys.stderr.write("[ERROR] %s\n" % msg[1])
  sys.exit(1)

try:
  sock.connect((HOST, PORT))
except socket.error as msg:
  sys.stderr.write("[ERROR] %s\n" % msg[1])
  sys.exit(2)

msg = {'@message': file_report_response, '@tags': ['python', 'test']}

sock.send(str(json.dumps(msg) ).encode('utf-8'))

sock.close()
sys.exit(0)