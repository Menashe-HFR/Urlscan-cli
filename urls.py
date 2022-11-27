from pathlib import Path
from urlscan import *


class Url:
    """
    A class to represent URL.
    """
    def __init__(self, url: str):
        self.url = url
        self.url_status = ''
        self.num_of_ips = ''
        self.valid_time = ''
        self.screenshot_url = ''
        self.suspicious_malicious = ''
        self.suspicious_categories = ''
        self.suspicious_score = ''

    def search_in_urlscan(self) -> dict:
        """
        This function requests search results from Urlscan.io and returns the results.
        """
        url = self.clean_url()
        search_url = API_URL + 'page.url:' + url + ' AND date:>now-365d'
        response = requests.get(search_url, headers=HEADERS)
        assert response.status_code == 200, f'response code is {response.status_code}'
        return response.json()

    def clean_url(self) -> str:
        """
        This function cleans the URL to be valid for search in the API.
        """
        url = self.url
        prefix = ['https://', 'http://']
        for p in prefix:
            if p in url:
                url = url.replace(p, '')
        if '/' in url:
            url = url.replace('/', '\/')

        return url

    def parsing_data(self, data: dict):
        """
        This function assigns values to variables from the API request result.
        """
        self.url_status = data['results'][0]['page']['status']
        self.num_of_ips = data['results'][0]['stats']['uniqIPs']
        self.screenshot_url = data['results'][0]['screenshot']
        try:
            self.valid_time = data['results'][0]['page']['tlsValidDays']
        except KeyError:
            print(f'{self.url} does not have a "tlsValidDays" ')

        result_url = data['results'][0]['result']
        response = requests.get(result_url, headers=HEADERS)
        if response.status_code == 200:
            results = response.json()
            self.suspicious_malicious = results['verdicts']['overall']['malicious']
            self.suspicious_score = results['verdicts']['overall']['score']
            if self.suspicious_malicious:
                self.suspicious_categories = results['verdicts']['overall']['categories']

    def get_data(self) -> dict:
        """
        This function returns all class variables as a dictionary
        """
        return {'url': self.url,
                'url_status': self.url_status,
                'num_of_ips': self.num_of_ips,
                'valid_time': self.valid_time,
                'suspicious_malicious': self.suspicious_malicious,
                'suspicious_categories': self.suspicious_categories,
                'suspicious_score': self.suspicious_score
                }

    def save_image(self):
        """
        This function saves the screenshot as a file.
        """
        Path('./screenshots').mkdir(parents=True, exist_ok=True)
        pic = requests.get(self.screenshot_url, headers=HEADERS)
        if pic.status_code == 200:
            with open(f'./screenshots/pic{self.screenshot_url[-8:-4]}.jpg', 'wb') as f:
                f.write(pic.content)
