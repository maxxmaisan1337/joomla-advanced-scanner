from flask import Flask, request, jsonify, send_file
from joomla import detect_plugins, detect_templates, detect_version, lookup_cve, brute_force_admin, scan_sqli_lfi

app = Flask(__name__)

@app.route('/')
def homepage():
    return send_file('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')
    option = data.get('option')

    result = ""

    if option == 'plugins':
        plugins = detect_plugins(url)
        result = "\n".join(plugins) if plugins else "No plugins detected."
    elif option == 'templates':
        detect_templates(url)
        result = "Template detection completed. Check console for results."
    elif option == 'version':
        version = detect_version(url)
        result = f"Version: {version}\nCVEs fetched successfully."
    elif option == 'bruteforce':
        brute_force_admin(url)
        result = "Brute force scan completed. Check console for details."
    elif option == 'sqli':
        scan_sqli_lfi(url)
        result = "SQLi / LFI scan completed. Check console for results."
    elif option == 'full':
        detect_plugins(url)
        detect_templates(url)
        version = detect_version(url)
        lookup_cve(version)
        brute_force_admin(url)
        scan_sqli_lfi(url)
        result = "Full scan completed. Check console for details."
    else:
        result = "Invalid scan option selected."

    return jsonify({"result": result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
