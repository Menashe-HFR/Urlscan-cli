import requests
import argparse
import json
import csv
import urls
from time import sleep


API_KEY = '878693f9-e5fc-4a1b-a114-caf85f03e67a'
API_URL = 'https://urlscan.io/api/v1/search/?q='
HEADERS = {'API-Key': API_KEY, 'Content-Type': 'application/json'}


def main(argv: str = None):
    """
    Getting arguments, running a search, and saving results.
    """
    arg = parse_arg(argv)
    file_lines = read_lines_from_file(arg)
    res = scan_url(file_lines)
    save_results(res)


def parse_arg(arg: str = None) -> str:
    """
    This function parsing arguments and returning them.
    """
    parser = argparse.ArgumentParser(usage="<urlscan.py> <path to urls.text>")
    parser.add_argument('file_name')
    return parser.parse_args(arg).file_name


def scan_url(urls_list: list) -> list:
    """
    This function runs a search in Urlscan.io parsing the result and saving them,
    saving the screenshot, and submitting a URL to be scanned if needed.
    """
    res = []

    for url in urls_list:
        u = urls.Url(url)
        search_res = u.search_in_urlscan()
        if not search_res['results']:
            post_url(u.clean_url())
            search_res = u.search_in_urlscan()

        if search_res['results']:
            u.parsing_data(search_res)
            u.save_image()
        res.append(u.get_data())

    return res


def save_results(res: list):
    """
    This function saves the results to a CSV file.
    """
    csv_col = list(res[0].keys())
    with open('urlscan_results.csv', 'w') as file:
        writer = csv.DictWriter(file, fieldnames=csv_col)
        writer.writeheader()
        for row in res:
            writer.writerow(row)


def read_lines_from_file(file: str) -> list:
    """
    This function reads the URLs from the file.
    """
    with open(file, 'r') as f:
        return f.read().splitlines()


def post_url(url: str):
    """
    This function sends URLs to be scanned.
    """
    data = {"url": url, "visibility": "public"}
    requests.post('https://urlscan.io/api/v1/scan/', headers=HEADERS, data=json.dumps(data))
    sleep(40)


if __name__ == '__main__':
    main()
