#!/usr/bin/env python3
import http.server
import json
import urllib.request

class IPGuardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_json({"status": "healthy", "service": "IPGuard Enterprise API", "version": "1.0.0"})
            return
        elif self.path.startswith("/v1/lookup"):
            ip = "8.8.8.8"
            self.send_json({
                "ip": ip,
                "country": "United States",
                "country_code": "US",
                "region": "California",
                "city": "Mountain View",
                "isp": "Google LLC",
                "proxy": False,
                "vpn": False,
                "tor": False,
                "fraud_score": 2,
                "risk_level": "LOW"
            })
            return
        self.send_error(404, "Not Found")

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", 8080), IPGuardHandler)
    print("IPGuard API running on 8080")
    server.serve_forever()
