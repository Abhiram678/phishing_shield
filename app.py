"""Phishing Shield - Phishing URL Detection Tool."""

from flask import Flask, render_template, request, jsonify
import urllib.parse
import logging
from utils.url_analyzers import analyze_url

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = app.logger

@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')

@app.route('/about')
def about():
    """Render the about page."""
    return render_template('about.html')

@app.route('/history')
def history():
    """Render the history page."""
    return render_template('history.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analyze a URL for phishing indicators.

    Returns:
        JSON response with analysis results.
    """
    try:
        data = request.get_json()

        if not data:
            logger.error("Invalid or missing JSON data")
            return jsonify({'error': 'Invalid JSON data'}), 400

        url = data.get('url')

        if not url:
            logger.error("No URL provided in request")
            return jsonify({'error': 'No URL provided'}), 400

        logger.info(f"Analyzing URL: {url}")

        # Analyze the URL
        results = analyze_url(url)

        # Log the result structure (for debugging)
        logger.debug(f"Analysis results keys: {results.keys() if isinstance(results, dict) else 'not a dict'}")

        # Check for errors in analysis
        if isinstance(results, dict) and 'error' in results:
            logger.error(f"Analysis error: {results['error']}")
            return jsonify(results), 500

        return jsonify(results)

    except Exception as e:
        logger.exception(f"Unhandled exception in analyze endpoint: {str(e)}")
        return jsonify({'error': f"Analysis failed: {str(e)}"}), 500

@app.route('/debug/<path:test_url>')
def debug(test_url):
    """Debug route to test URL analysis components individually."""
    try:
        # Ensure URL has protocol
        if not test_url.startswith(('http://', 'https://')):
            test_url = 'https://' + test_url

        parsed_url = urllib.parse.urlparse(test_url)

        results = {
            'url': test_url,
            'parsed_url': {
                'scheme': parsed_url.scheme,
                'netloc': parsed_url.netloc,
                'path': parsed_url.path,
                'params': parsed_url.params,
                'query': parsed_url.query,
                'fragment': parsed_url.fragment
            },
            'domain': parsed_url.netloc
        }

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)