from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

PORT = 8000

class LogHTTPHandler(BaseHTTPRequestHandler):
    buffer = 1
    log_file = open('./logfile.txt', 'w', buffer)
    def log_message(self, format, *args):
        self.log_file.write("%s - - [%s] %s\n" %
                            (self.client_address[0],
                             self.log_date_time_string(),
                             format%args))

Handler = LogHTTPHandler

httpd = HTTPServer(("", PORT), Handler)

print("serving at port", PORT)

httpd.serve_forever()

