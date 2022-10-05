data = """
GET https://sts.amazonaws.com%2F?Action=GetCallerIdentity&Version=2011-06-15
authorization: AWS4-HMAC-SHA256 Credential=AKIA6B26NHU5O5YSUKLM/20210515/us-east-1/sts/aws4_request, SignedHeaders=content-type;hello;host;x-amz-content-sha256;x-amz-date, Signature=2ec86769dcc19f22a88cf8551cbf7663394b7ea331d6fc70f546a9ad8f48ee43
content-length: 0
content-type: application/octet-stream
hello: ÿ
host: sts.amazonaws.com
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20210515T062543Z
"""

data = data.strip().split("\n")
from urllib.error import HTTPError
from urllib.request import Request, urlopen
url = data[0].split()[1]
headers = {}
for header_line in data[1:]:
    key, value = header_line.split(":", 1)
    if key == "hello":
        value = b"\xff\xff\xff"
    else:
        value = value.encode("utf-8")
    headers[key] = value

req = Request(url, headers=headers)
try:
    print(urlopen(req))
except HTTPError as e:
    print(e)
    print(e.read())