from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import hashlib

options = Options()
options.add_argument("--headless=new")
driver = webdriver.Chrome(service=Service(), options=options)

# ---------------- CHANGE THIS PATH TO ANY FILE(not a folder) ------------------
path = r"D:\Clients\Horion1.21.81 .dll"
# ------------------------------------------------------------------------------

with open(path, "rb") as f:
    raw_bytes = f.read()
    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()


driver.get(f"https://www.virustotal.com/gui/file/{sha256_hash}")
js = """
try {
  return document
    .querySelector("#view-container > file-view")?.shadowRoot
    ?.querySelector("#detectionsList")?.shadowRoot
    ?.querySelector("#detections")?.innerText || "[ERROR]: Element not found";
} catch (e) {
  return "[ERROR]: " + e.message;
}
"""
output = driver.execute_script(js).split('\n')
driver.quit()

AVs = output[::2]
Detections = output[1::2]
malwareCount = 0
count = 0
for detection in Detections:
    if detection != 'Undetected' and detection != 'Unable to process file type':
        malwareCount += 1
        print(f"    {AVs[Detections.index(detection)]  }    says   {detection}")
    count += 1
print(f"{malwareCount} / {count} say ur file is malware")
print(f'ur file could be: {(malwareCount/count) * 100} % a malware')