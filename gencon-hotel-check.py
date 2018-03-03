#!/usr/bin/env python3
import html.parser
import json
import re
import ssl
import sys
import threading
import urllib
import urllib.error
import urllib.parse
import urllib.request
from argparse import Action, ArgumentParser, ArgumentTypeError, SUPPRESS
from datetime import datetime, timedelta
from time import sleep

FIRST_DAY = datetime(2018, 7, 28)
LAST_DAY = datetime(2018, 8, 7)
EVENT_START_DAY = datetime(2018, 8, 2)
EVENT_URL = 'https://aws.passkey.com/event/49547714/owner/10909638/rooms/select'

DISTANCE_UNITS = {
    1: 'blocks',
    2: 'yards',
    3: 'miles',
    4: 'meters',
    5: 'kilometers',
}

class PasskeyParser(html.parser.HTMLParser):
    def __init__(self, resp):
        HTMLParser.__init__(self)
        self.json = None
        self.feed(resp.read())
        self.close()

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'script':
            attrs = dict(attrs)
            if attrs.get('id', '').lower() == 'last-search-results':
                self.json = True

    def handle_data(self, data):
        if self.json is True:
            self.json = data


class EmailAction(Action):
    def __call__(self, parser, namespace, values, option_string=None):
        dest = getattr(namespace, self.dest)
        if dest is None:
            dest = []
            setattr(namespace, self.dest, dest)
        dest.append(tuple(['email'] + values))


def parse_args():
    '''
    Parses the command line arguments and generates help text.
    '''
    parser = ArgumentParser()

    # Optional
    parser.add_argument('--guests', type = int, default = 1, help = 'number of guests')
    parser.add_argument('--children', type = int, default = 0, help = 'number of children')
    parser.add_argument('--rooms', type = int, default = 1, help = 'number of rooms')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--checkin', type = parse_date, metavar = 'YYYY-MM-DD', default = EVENT_START_DAY.strftime('%Y-%m-%d'), help = 'check in')
    group.add_argument('last_notifications = set()--wednesday', dest = 'checkin', action = 'store_const', const = (EVENT_START_DAY - timedelta(1)).strftime('%Y-%m-%d'), help = 'check in on Wednesday')
    parser.add_argument('--checkout', type = parse_date, metavar = 'YYYY-MM-DD', default = (EVENT_START_DAY + timedelta(3)).strftime('%Y-%m-%d'), help = 'check out')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--max-distance', type = parse_distance, metavar = 'BLOCKS', help = "max hotel distance that triggers an alert (or 'connected' to require skywalk hotels)")
    group.add_argument('--connected', dest = 'max_distance', action = 'store_const', const = 'connected', help = 'shorthand for --max-distance connected')
    parser.add_argument('--budget', type = float, metavar = 'PRICE', default = '99999', help = 'max total rate (not counting taxes/fees) that triggers an alert')
    parser.add_argument('--hotel-regex', type = parse_regex, metavar = 'PATTERN', default = re.compile('.*'), help = 'regular expression to match hotel name against')
    parser.add_argument('--room-regex', type = parse_regex, metavar = 'PATTERN', default = re.compile('.*'), help = 'regular expression to match room against')
    parser.add_argument('--show-all', action = 'store_true', help = 'show all rooms, even if miles away (these rooms never trigger alerts)')
    parser.add_argument('--ssl-insecure', action = 'store_false', dest = 'ssl_cert_verify', help = SUPPRESS)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--delay', type = int, default = 1, metavar = 'MINS', help = 'search every MINS minute(s)')
    group.add_argument('--once', action = 'store_true', help = 'search once and exit')
    parser.add_argument('--test', action = 'store_true', dest = 'test', help = 'trigger every specified alert and exit')

    # Required
    group = parser.add_argument_group('required arguments')
    group.add_argument('--key', required = True, help = 'key (see the README for more information)')

    # Alerts
    group = parser.add_argument_group('alerts')
    group.add_argument('--cmd', dest = 'alerts', action = 'append', type = lambda arg: ('cmd', arg), metavar = 'CMD', help = 'run the specified command, passing each hotel name as an argument')

    return parser.parse_args()


def parse_date(arg):
    '''
    Parse command line input as a date.
    '''
    try:
        d = datetime.strptime(arg, '%Y-%m-%d')
    except ValueError:
        raise ArgumentTypeError("{0} is not a date in the form YYYY-MM-DD".format(arg))
    if not FIRST_DAY <= d <= LAST_DAY:
        raise ArgumentTypeError("{0} is outside the Gencon housing block window".format(arg))
    return arg


def parse_distance(arg):
    '''
    Parses command line input as a distance.
    '''
    if arg == 'connected':
        return arg
    try:
        return float(arg)
    except ValueError:
        raise ArgumentTypeError("invalid float value: '{0}'".format(arg))


def parse_regex(arg):
    '''
    Parses command line input as a regular expression.
    '''
    try:
        return re.compile(arg, re.IGNORECASE)
    except Exception as e:
        raise ArgumentTypeError("invalid regex '{0}': {0}".format(arg, e))


def configure_notifications(config):
    '''
    Parses the configuration and creates appropriate notification handlers.
    '''
    notification_handlers = []
    for alert in config.alerts or []:
        if alert[0] == 'cmd':
            import subprocess
            notification_handlers.append(lambda preamble, hotels, cmd = alert[1]: subprocess.Popen([cmd] + [hotel['name'] for hotel in hotels]))
    return notification_handlers


def test_alerts(alert_handlers):
    '''
    Verifies that the cnonfigured alerts are functioning.
    '''
    print("Testing alerts one at a time...")
    preamble = 'This is a test'
    hotels = [
        { 'name': 'Test hotel 1', 'distance': '2 blocks', 'rooms': 1, 'room': 'Queen/Queen suite' },
        { 'name': 'Test hotel 2', 'distance': '5 blocks', 'rooms': 5, 'room': 'Standard King' }
    ]
    for fn in alert_handlers:
        fn(preamble, hotels)
    print("Done")


def get_session_cookie(url, ssl_context):
    '''
    Fetches the user session cookie.
    '''
    try:
        resp = urllib.request.urlopen(url, context=ssl_context)
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLError) and e.reason.reason == 'CERTIFICATE_VERIFY_FAILED':
            print(e)
            print()
            print("If Python is having trouble finding your local certificate store, you can bypass this check with --ssl-insecure")
            exit(1)
        raise Exception("Session request failed: {0}".format(e))

    if resp.getcode() != 200:
        raise Exception("Session request failed: {0}".format(resp.getcode()))

    if 'Set-Cookie' not in resp.info():
        raise Exception("No session cookie received. Is your key correct?")

    return resp.info()['Set-Cookie']


def search(args, cookie, url, ssl_context):
    '''
    Fetches the hotels that match the configured options.
    '''
    try:
        # Set search filter
        print("Searching... ({0} {1}, {2} {3}, {4} - {5}, {6})"
            .format(args.guests, 'guest' if args.guests == 1 else 'guests',
            args.rooms, 'room' if args.rooms == 1 else 'rooms', args.checkin,
            args.checkout, 'connected' if args.max_distance == 'connected' else 'downtown' if args.max_distance is None else "within %.1f blocks" % args.max_distance))

        headers = { 'Cookie': cookie }
        data = {
            'hotelId': '0',
            'blockMap.blocks[0].blockId': '0',
            'blockMap.blocks[0].checkIn': args.checkin,
            'blockMap.blocks[0].checkOut': args.checkout,
            'blockMap.blocks[0].numberOfGuests': str(args.guests),
            'blockMap.blocks[0].numberOfRooms': str(args.rooms),
            'blockMap.blocks[0].numberOfChildren': str(args.children),
        }

        data = urllib.parse.urlencode(data).encode('utf-8')
        request = urllib.request.Request(url, data=data, headers=headers)
        response = urllib.request.urlopen(request, context=ssl_context)

        if response.getcode() not in (200, 302):
            print("Search failed")
            return None

        parser = PasskeyParser(response)
        if not parser.json:
            print("Failed to find search results")
            return False

        return json.loads(parser.json)

    except urllib.error.URLError as e:
        print("Search failed")
        return None


last_notifications = set()
def parse_search_results(hotels, notification_handlers):
    '''
    Processes the search results and sends all configured notifications.
    '''
    global last_notifications

    print("Results:   ({}".format(datetime.now()))
    alerts = []

    print("   %-15s %-10s %-80s %s" % ('Distance', 'Price', 'Hotel', 'Room'))
    for hotel in hotels:
        for block in hotel['blocks']:
            # Don't show hotels miles away unless requested
            if hotel['distanceUnit'] == 3 and not args.show_all:
                continue

            connected = ('Skywalk to ICC' in (hotel['messageMap'] or ''))
            simple_hotel = {
                'name': parser.unescape(hotel['name']),
                'distance': 'Skywalk' if connected else "%4.1f %s" % (hotel['distanceFromEvent'], DISTANCE_UNITS.get(hotel['distanceUnit'], '???')),
                'price': int(sum(inv['rate'] for inv in block['inventory'])),
                'rooms': min(inv['available'] for inv in block['inventory']),
                'room': parser.unescape(block['name']),
            }
            result = "%-15s $%-9s %-80s (%d) %s" % (
                simple_hotel['distance'],
                simple_hotel['price'],
                simple_hotel['name'],
                simple_hotel['rooms'],
                simple_hotel['room']
            )
            # I don't think these distances (yards, meters, kilometers) actually appear in the results, but if they do assume it must be close enough regardless of --max-distance
            close_enough = hotel['distanceUnit'] in (2, 4, 5) or \
                          (hotel['distanceUnit'] == 1 and (args.max_distance is None or (isinstance(args.max_distance, float) and hotel['distanceFromEvent'] <= args.max_distance))) or \
                          (args.max_distance == 'connected' and connected)
            cheap_enough = simple_hotel['price'] <= args.budget
            name_match = args.hotel_regex.search(simple_hotel['name']) and args.room_regex.search(simple_hotel['room'])
            if close_enough and cheap_enough and name_match:
                alerts.append(simple_hotel)
                print(' !', end='')
            else:
                print('  ', end='')
            print(result)

    # Send Notifications.
    if alerts:
        alert_hash = {(alert['name'], alert['room']) for alert in alerts}
        if alert_hash <= last_notifications:
            print("Skipped alerts (no new rooms in nearby hotel list)")
        else:
            hotel_count = len(set(alert['name'] for alert in alerts))
            preamble = "%d %s near the ICC:" % (hotel_count, 'hotel' if hotel_count == 1 else 'hotels')
            for handler in alert_handlers:
                # Run each alert on its own thread since some (e.g. popups) are blocking and some (e.g. e-mail) can throw
                threading.Thread(target = handler, args = (preamble, alerts)).start()
            print("Triggered alerts")
    else:
        alert_hash = set()

    print()
    last_notifications = alert_hash
    return True


def main():
    '''
    The main executing code.
    '''
    config = parse_args()
    base_url = "https://aws.passkey.com/reg/%s/null/null/1/0/null" % config.key

    ssl_context = ssl.create_default_context()
    if not config.ssl_cert_verify:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    # Notifications
    notification_handlers = configure_notifications(config)

    if not notification_handlers:
        print('''
        Warning: You have no alert methods selected, so you're not going to know
        about a match unless you're staring at this window when it happens. See
        the README for more information.
        ''')

    if config.test:
        test_alerts(notification_handlers)
        exit(0)

    # Main Loop
    cookie = get_session_cookie(base_url, ssl_context)
    running = True
    while running:
        search_results = search(config, cookie, EVENT_URL, ssl_context)
        if search_results is not None:
            parse_search_results(search_results, notification_handlers)

        if config.once:
            running = False
        else:
            sleep(60 * config.delay)


if __name__ == '__main__':
    if sys.version_info < (3, 0, 0):
        print("Requires Python 3.0.0+")
        exit(1)

    main()
