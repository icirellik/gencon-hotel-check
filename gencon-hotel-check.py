#!/usr/bin/env python3
from argparse import Action, ArgumentParser, ArgumentTypeError, SUPPRESS
from datetime import datetime, timedelta
from html.parser import HTMLParser
from json import loads as fromJS
from os.path import abspath, dirname, join as pathjoin
import re
from ssl import create_default_context as create_ssl_context, CERT_NONE, SSLError
from sys import version_info
from threading import Thread
from time import sleep
import urllib

firstDay, lastDay, startDay = datetime(2018, 7, 28), datetime(2018, 8, 7), datetime(2018, 8, 2)
eventUrl = 'https://aws.passkey.com/event/49547714/owner/10909638/rooms/select'

distanceUnits = {
    1: 'blocks',
    2: 'yards',
    3: 'miles',
    4: 'meters',
    5: 'kilometers',
}

class PasskeyParser(HTMLParser):
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

def type_day(arg):
    try:
        d = datetime.strptime(arg, '%Y-%m-%d')
    except ValueError:
        raise ArgumentTypeError("{0} is not a date in the form YYYY-MM-DD".format(arg))
    if not firstDay <= d <= lastDay:
        raise ArgumentTypeError("{0} is outside the Gencon housing block window".format(arg))
    return arg

def type_distance(arg):
    if arg == 'connected':
        return arg
    try:
        return float(arg)
    except ValueError:
        raise ArgumentTypeError("invalid float value: '{0}'".format(arg))

def type_regex(arg):
    try:
        return re.compile(arg, re.IGNORECASE)
    except Exception as e:
        raise ArgumentTypeError("invalid regex '{0}': {0}".format(arg, e))

class EmailAction(Action):
    def __call__(self, parser, namespace, values, option_string=None):
        dest = getattr(namespace, self.dest)
        if dest is None:
            dest = []
            setattr(namespace, self.dest, dest)
        dest.append(tuple(['email'] + values))

if version_info < (3, 0, 0):
    print("Requires Python 3.0.0+")
    exit(1)

parser = ArgumentParser()
parser.add_argument('--guests', type = int, default = 1, help = 'number of guests')
parser.add_argument('--children', type = int, default = 0, help = 'number of children')
parser.add_argument('--rooms', type = int, default = 1, help = 'number of rooms')
group = parser.add_mutually_exclusive_group()
group.add_argument('--checkin', type = type_day, metavar = 'YYYY-MM-DD', default = startDay.strftime('%Y-%m-%d'), help = 'check in')
group.add_argument('--wednesday', dest = 'checkin', action = 'store_const', const = (startDay - timedelta(1)).strftime('%Y-%m-%d'), help = 'check in on Wednesday')
parser.add_argument('--checkout', type = type_day, metavar = 'YYYY-MM-DD', default = (startDay + timedelta(3)).strftime('%Y-%m-%d'), help = 'check out')
group = parser.add_mutually_exclusive_group()
group.add_argument('--max-distance', type = type_distance, metavar = 'BLOCKS', help = "max hotel distance that triggers an alert (or 'connected' to require skywalk hotels)")
group.add_argument('--connected', dest = 'max_distance', action = 'store_const', const = 'connected', help = 'shorthand for --max-distance connected')
parser.add_argument('--budget', type = float, metavar = 'PRICE', default = '99999', help = 'max total rate (not counting taxes/fees) that triggers an alert')
parser.add_argument('--hotel-regex', type = type_regex, metavar = 'PATTERN', default = re.compile('.*'), help = 'regular expression to match hotel name against')
parser.add_argument('--room-regex', type = type_regex, metavar = 'PATTERN', default = re.compile('.*'), help = 'regular expression to match room against')
parser.add_argument('--show-all', action = 'store_true', help = 'show all rooms, even if miles away (these rooms never trigger alerts)')
parser.add_argument('--ssl-insecure', action = 'store_false', dest = 'ssl_cert_verify', help = SUPPRESS)
group = parser.add_mutually_exclusive_group()
group.add_argument('--delay', type = int, default = 1, metavar = 'MINS', help = 'search every MINS minute(s)')
group.add_argument('--once', action = 'store_true', help = 'search once and exit')
parser.add_argument('--test', action = 'store_true', dest = 'test', help = 'trigger every specified alert and exit')

group = parser.add_argument_group('required arguments')
group.add_argument('--key', required = True, help = 'key (see the README for more information)')

group = parser.add_argument_group('alerts')
group.add_argument('--popup', dest = 'alerts', action = 'append_const', const = ('popup',), help = 'show a dialog box')
group.add_argument('--cmd', dest = 'alerts', action = 'append', type = lambda arg: ('cmd', arg), metavar = 'CMD', help = 'run the specified command, passing each hotel name as an argument')
group.add_argument('--browser', dest = 'alerts', action = 'append_const', const = ('browser',), help = 'open the Passkey website in the default browser')
group.add_argument('--email', dest = 'alerts', action = EmailAction, nargs = 3, metavar = ('HOST', 'FROM', 'TO'), help = 'send an e-mail')

args = parser.parse_args()
startUrl = "https://aws.passkey.com/reg/%s/null/null/1/0/null" % args.key

sslCtx = create_ssl_context()
if not args.ssl_cert_verify:
    sslCtx.check_hostname = False
    sslCtx.verify_mode = CERT_NONE

# Setup the alert handlers
alertFns = []
success = True
for alert in args.alerts or []:
    if alert[0] == 'popup':
        try:
            import win32api
            alertFns.append(lambda preamble, hotels: win32api.MessageBox(0, 'Gencon Hotel Search', "%s\n\n%s" % (preamble, '\n'.join("%s: %s: %s" % (hotel['distance'], hotel['name'], hotel['room']) for hotel in hotels))))
        except ImportError:
            try:
                import Tkinter, tkMessageBox
                def handle(preamble, hotels):
                    window = Tkinter.Tk()
                    window.wm_withdraw()
                    tkMessageBox.showinfo(title = 'Gencon Hotel Search', message = "%s\n\n%s" % (preamble, '\n'.join("%s: %s: %s" % (hotel['distance'], hotel['name'], hotel['room']) for hotel in hotels)))
                    window.destroy()
                alertFns.append(handle)
            except ImportError:
                print("Unable to show a popup. Install either win32api (if on Windows) or Tkinter")
                success = False
    elif alert[0] == 'cmd':
        import subprocess
        alertFns.append(lambda preamble, hotels, cmd = alert[1]: subprocess.Popen([cmd] + [hotel['name'] for hotel in hotels]))
    elif alert[0] == 'browser':
        import webbrowser
        alertFns.append(lambda preamble, hotels: webbrowser.open(startUrl))
    elif alert[0] == 'email':
        from email.mime.text import MIMEText
        import getpass, smtplib, socket
        _, host, fromEmail, toEmail = alert
        password = getpass.getpass("Enter password for %s (or blank if %s requires no authentication): " % (fromEmail, host))
        def smtpConnect():
            try:
                smtp = smtplib.SMTP_SSL(host)
            except socket.error:
                smtp = smtplib.SMTP(host)
            if password:
                smtp.login(fromEmail, password)
            return smtp
        try:
            smtpConnect()
            def handle(preamble, hotels):
                msg = MIMEText("%s\n\n%s\n\n%s" % (preamble, '\n'.join("  * %s: %s: %s" % (hotel['distance'], hotel['name'].encode('utf-8'), hotel['room'].encode('utf-8')) for hotel in hotels), startUrl), 'plain', 'utf-8')
                msg['Subject'] = 'Gencon Hotel Search'
                msg['From'] = fromEmail
                msg['To'] = toEmail
                smtpConnect().sendmail(fromEmail, toEmail, msg.as_string())
            alertFns.append(handle)
        except Exception as e:
            print(e)
            success = False

if not success:
    exit(1)

if not alertFns:
    print("Warning: You have no alert methods selected, so you're not going to know about a match unless you're staring at this window when it happens. See the README for more information")
    print()

if args.test:
    print("Testing alerts one at a time...")
    preamble = 'This is a test'
    hotels = [{'name': 'Test hotel 1', 'distance': '2 blocks', 'rooms': 1, 'room': 'Queen/Queen suite'}, {'name': 'Test hotel 2', 'distance': '5 blocks', 'rooms': 5, 'room': 'Standard King'}]
    for fn in alertFns:
        fn(preamble, hotels)
    print("Done")
    exit(0)

lastAlerts = set()

def sessionSetup():
    try:
        resp = urlopen(startUrl, context = sslCtx)
    except URLError as e:
        if isinstance(e.reason, SSLError) and e.reason.reason == 'CERTIFICATE_VERIFY_FAILED':
            print(e)
            print()
            print("If Python is having trouble finding your local certificate store, you can bypass this check with --ssl-insecure")
            exit(1)
        print("Session request failed: {0}".format(e))
        return None
    if resp.getcode() != 200:
        print("Session request failed: {0}".format(resp.getcode()))
        return None

    if 'Set-Cookie' not in resp.info():
        print("No session cookie received. Is your key correct?")
        return None
    cookies = resp.info()['Set-Cookie'].split(', ')
    cookies = map(lambda cookie: cookie.split(';')[0], cookies)
    headers = {'Cookie': ';'.join(cookies)}

    # Set search filter
    print("Searching... ({0} {1}, {2} {3}, {4} - {5}, {6})"
        .format(args.guests, 'guest' if args.guests == 1 else 'guests',
        args.rooms, 'room' if args.rooms == 1 else 'rooms', args.checkin,
        args.checkout, 'connected' if args.max_distance == 'connected' else 'downtown' if args.max_distance is None else "within %.1f blocks" % args.max_distance))
    data = {
        'hotelId': '0',
        'blockMap.blocks[0].blockId': '0',
        'blockMap.blocks[0].checkIn': args.checkin,
        'blockMap.blocks[0].checkOut': args.checkout,
        'blockMap.blocks[0].numberOfGuests': str(args.guests),
        'blockMap.blocks[0].numberOfRooms': str(args.rooms),
        'blockMap.blocks[0].numberOfChildren': str(args.children),
    }
    try:
        resp = urlopen(Request(eventUrl, urllib.parse.urlencode(data), headers), context = sslCtx)
    except URLError:
        resp = None
    if resp is None or resp.getcode() not in (200, 302):
        print("Search failed")
        return None
    return resp

def search(resp):
    global lastAlerts

    parser = PasskeyParser(resp)
    if not parser.json:
        print("Failed to find search results")
        return False

    hotels = fromJS(parser.json)

    print("Results:   ({}".format(datetime.now()))
    alerts = []

    print("   %-15s %-10s %-80s %s" % ('Distance', 'Price', 'Hotel', 'Room'))
    for hotel in hotels:
        for block in hotel['blocks']:
            # Don't show hotels miles away unless requested
            if hotel['distanceUnit'] == 3 and not args.show_all:
                continue

            connected = ('Skywalk to ICC' in (hotel['messageMap'] or ''))
            simpleHotel = {
                'name': parser.unescape(hotel['name']),
                'distance': 'Skywalk' if connected else "%4.1f %s" % (hotel['distanceFromEvent'], distanceUnits.get(hotel['distanceUnit'], '???')),
                'price': int(sum(inv['rate'] for inv in block['inventory'])),
                'rooms': min(inv['available'] for inv in block['inventory']),
                'room': parser.unescape(block['name']),
            }
            result = "%-15s $%-9s %-80s (%d) %s" % (simpleHotel['distance'], simpleHotel['price'], simpleHotel['name'], simpleHotel['rooms'], simpleHotel['room'])
            # I don't think these distances (yards, meters, kilometers) actually appear in the results, but if they do assume it must be close enough regardless of --max-distance
            closeEnough = hotel['distanceUnit'] in (2, 4, 5) or \
                          (hotel['distanceUnit'] == 1 and (args.max_distance is None or (isinstance(args.max_distance, float) and hotel['distanceFromEvent'] <= args.max_distance))) or \
                          (args.max_distance == 'connected' and connected)
            cheapEnough = simpleHotel['price'] <= args.budget
            regexMatch = args.hotel_regex.search(simpleHotel['name']) and args.room_regex.search(simpleHotel['room'])
            if closeEnough and cheapEnough and regexMatch:
                alerts.append(simpleHotel)
                print(' !', end='')
            else:
                print('  ', end='')
            print(result)

    if alerts:
        alertHash = {(alert['name'], alert['room']) for alert in alerts}
        if alertHash <= lastAlerts:
            print("Skipped alerts (no new rooms in nearby hotel list)")
        else:
            numHotels = len(set(alert['name'] for alert in alerts))
            preamble = "%d %s near the ICC:" % (numHotels, 'hotel' if numHotels == 1 else 'hotels')
            for fn in alertFns:
                # Run each alert on its own thread since some (e.g. popups) are blocking and some (e.g. e-mail) can throw
                Thread(target = fn, args = (preamble, alerts)).start()
            print("Triggered alerts")
    else:
        alertHash = set()

    print()
    lastAlerts = alertHash
    return True


while True:
    resp = sessionSetup()
    if resp is not None:
        search(resp)
        if args.once:
            exit(0)
    sleep(60 * args.delay)

if __name__ == '__main__':

    print('fiddler')


