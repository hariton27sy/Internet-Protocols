import os
import re


def get_user():
    try:
        query = os.environ['QUERY_STRING']
    except KeyError:
        return 'Anonymous'

    match = re.search(r'name=(.*?)($|&.*)', query)
    if not match:
        return 'Anonymous'
    return match.group(1)


def print_page(user: str):
    content = f'''<html>
    <head>
        <title>Test page</title>
    </head>
    <body>
        <h1>Hello, {user}!</h1>
    </body>    
</html>'''
    headers = f"""HTTP/1.0 200 OK
Content-Type: text/html
Content-Length: {len(content)}"""
    print(headers)
    print()
    print(content)


if __name__ == "__main__":
    print_page(get_user())

