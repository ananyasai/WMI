import re

def detect_obfuscation(php_code):
    # Regular expressions to detect common obfuscation patterns
    regex_patterns = [
        #r'\$\w{20,}',           # Matches variables with long and random names
        # r'base64_decode',      # Matches calls to base64_decode function
        r'base64_decode[\s\(]',  # Matches calls to base64_decode function
        # r'eval\s*\(',          # Matches calls to eval function
        r'eval[\s\(]',          # Matches calls to eval function
        # r'gzinflate',          # Matches calls to gzinflate function
        r'create_function',    # Matches calls to create_function
        # r'assert\s*\(',        # Matches calls to assert function
        # r'chr\s*\(',           # Matches calls to chr function
        # r'ord\s*\(',           # Matches calls to ord function
        r'\\x[0-9a-fA-F]{2}',  # Matches hexadecimal escapes (e.g., \xXX)
        r'\\\d{3}',            # Matches octal escapes (e.g., \123)
        r'^[A-Za-z0-9]+$',     # Jumbled letters and numbers only in the entire line
        # r'/\*[a-z0-9]+\*/',    # /*6g33*/ pattern
        r'my_sucuri_encoding', # Legit sucuri file that look slike bad file
        r'\'.\'=>\'.\'',       # Array map obfus
        r'chr\([0-9]+\)',      # int to ascii
        r'\$[0Oo]+[{=]',
        r'\$__=\$__.',
        r'chr\([0-9]+\)',
        r'gzinflate[\s\(]',    # int to ascii
        r'\$[li]+[{=]'

    ]

    matched_patterns = []
    for pattern in regex_patterns:
        if re.search(pattern, php_code):
            matched_patterns.append(pattern)
            #print(pattern)


    return matched_patterns

if __name__ == "__main__":
    file_path = "path/to/your/php_file.php"
    with open(file_path, "r") as file:
        php_code = file.read()

    if detect_obfuscation(php_code):
        print("Obfuscation detected!")
    else:
        print("No obfuscation detected.")
