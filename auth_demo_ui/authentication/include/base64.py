import base64

def base64_url_safe_string(data):
    data = base64.b64encode(data)
    data = data.decode("utf-8")
    data = data.replace('+', '-').replace('/', '_').rstrip('=')
    
    return data

def base64_url_decode(base64URL):
    base64_string = base64URL.replace("-", "+").replace("_", "/")
    
    padding = len(base64_string) % 4
    
    if padding > 0:
        base64_string += "=" * padding
        
    result = base64.b64decode(base64_string)
    
    return result