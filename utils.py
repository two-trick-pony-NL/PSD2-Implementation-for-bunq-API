from colorama import init, Fore, Back, Style
import requests

init(autoreset=True)

COLOR_MAP = {
    "black": Fore.BLACK,
    "red": Fore.RED,
    "green": Fore.GREEN,
    "yellow": Fore.YELLOW,
    "blue": Fore.BLUE,
    "magenta": Fore.MAGENTA,
    "cyan": Fore.CYAN,
    "white": Fore.WHITE,
}

STYLE_MAP = {
    "bright": Style.BRIGHT,
    "dim": Style.DIM,
    "normal": Style.NORMAL,
}

BG_MAP = {
    "black": Back.BLACK,
    "red": Back.RED,
    "green": Back.GREEN,
    "yellow": Back.YELLOW,
    "blue": Back.BLUE,
    "magenta": Back.MAGENTA,
    "cyan": Back.CYAN,
    "white": Back.WHITE,
}

def cprint(text, color=None, style=None, bg=None):
    parts = []
    if color in COLOR_MAP:
        parts.append(COLOR_MAP[color])
    if style in STYLE_MAP:
        parts.append(STYLE_MAP[style])
    if bg in BG_MAP:
        parts.append(BG_MAP[bg])
    print("".join(parts) + str(text))

_orig_request = requests.Session.request


def log_request(self, method, url, *args, **kwargs):
    response = _orig_request(self, method, url, *args, **kwargs)

    banner = "=" * 60
    print(f"\n{banner}")
    if response.status_code >= 200 and response.status_code <= 299:
        cprint(f"{method.upper()} request to:", color="green", style="bright")
        cprint(f"{url}", color="cyan", style="bright")
        cprint(f"Response Status Code:         {response.status_code}", color="cyan", style="bright")

    else:
        cprint(f"{method.upper()} request to:", color="red", style="bright")
        cprint(f"{url}", color="red", style="bright")
        cprint(f"Response Status Code:         {response.status_code}", color="red", style="bright")

    print(f"{banner}")

    # Request Headers
    headers = kwargs.get('headers') or {}
    if headers:
        print("Request Headers:")
        for k, v in headers.items():
            print(f"  {k:30}: {v}")
    # Bunq Response ID
    response_id = response.headers.get('x-bunq-client-response-id', 'N/A')
    if response.status_code >= 200 and response.status_code <= 299:
        print(f"Bunq Response ID:             {response_id}")
    else:
        cprint(f"Bunq Response ID:             {response_id}", color="red", style="bright")


    # Payload / JSON
    data = kwargs.get('data') or kwargs.get('json')
    if data:
        print(f"Payload/Data:                 {data}")

    # If not successful, dump response body
    if not (200 <= response.status_code < 300):
        error_banner = "-" * 60
        print(f"\n{error_banner}")
        cprint(f"Response body", color="red", style="bright")

        try:
            print("\n")
            print(response.json())
        except Exception:
            print(response.text)
        print(f"{error_banner}")
            
    spacing = "\n" * 5 
    print(spacing)
    return response