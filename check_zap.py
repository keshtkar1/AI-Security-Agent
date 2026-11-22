
from app.services.zap_service import zap_service

result = zap_service.is_connected()

if result["connected"]:
    print("[SUCCESS] ZAP Service is working")
    print("ZAP Version:", result["version"])
else:
    print("[ERROR] ZAP Service connection failed")
    print("Details:", result["error"])
