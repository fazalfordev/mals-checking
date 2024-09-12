import PyPDF2
from flask import Flask, request, jsonify
from PIL import Image
import re

app = Flask(__name__)

patterns = [
    re.compile(b'<script.*?>.*?</script>', re.IGNORECASE | re.DOTALL),  # Detect <script> tags with content
    re.compile(b'/JavaScript', re.IGNORECASE),
    re.compile(b'<\?php.*?\?>', re.IGNORECASE | re.DOTALL),  # Detect PHP code
    re.compile(b'&#x25', re.IGNORECASE),
    re.compile(b'local_dtd', re.IGNORECASE),
    re.compile(b'/XInclude', re.IGNORECASE),
]

def is_malicious_pdf(file_stream):
    try:
        binary_content = file_stream.read()
        
        # Check for suspicious patterns in the binary content
        for pattern in patterns:
            if re.search(pattern, binary_content):
                return True
        
        file_stream.seek(0)  # Reset file pointer to beginning
        reader = PyPDF2.PdfReader(file_stream)
        content = ""
        for page in reader.pages:
            content += page.extract_text()
        
        # Check for suspicious patterns in the extracted text
        for pattern in patterns:
            if re.search(pattern.decode(), content):
                return True

    except Exception as e:
        pass

    return False

def is_malicious_image(file_stream):
    try:
        with Image.open(file_stream) as img:
            # Check for suspicious keywords in image metadata
            metadata = img.info
            for key, value in metadata.items():
                if isinstance(value, str):
                    for pattern in patterns:
                        if re.search(pattern.decode(), value):
                            return True
    except Exception as e:
        pass

    return False

@app.route('/check-file', methods=['POST'])
def check_file():
    file = request.files['file']
    filename = file.filename

    # Check if the file is a PDF
    if filename.lower().endswith('.pdf'):
        if is_malicious_pdf(file.stream):  # Pass the file stream directly
            return jsonify({"is_malicious": True})
        else:
            return jsonify({"is_malicious": False})

    # Check if the file is an image
    elif filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        if is_malicious_image(file.stream):  # Pass the file stream directly
            return jsonify({"is_malicious": True})
        else:
            return jsonify({"is_malicious": False})
    
    else:
        return jsonify({"error": "Unsupported file type"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
