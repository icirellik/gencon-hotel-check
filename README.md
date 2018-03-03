This script polls the Gencon housing website looking for hotel rooms near the
ICC, and alerts you in a variety of ways when available rooms are found. It
requires [Python](https://www.python.org/) 3+.

This was most recently updated for Gencon 2018. If it's currently a later year,
I'll probably be putting out an update soon after housing opens. If that
doesn't happen, you can probably figure out [what to edit](https://github.com/mrozekma/gencon-hotel-check/blob/master/gencon-hotel-check.py#L16-L17)
to get it working assuming nothing major has changed on the housing website.

## Output

The columns in the script's output are:

* `Distance` -- How far away the hotel is. By default only rooms in the "blocks"
range are shown, as these are the only rooms the script will ever care alert you
about, but `--show-all` will also show the hotels miles away. "Skywalk" means
the hotel is connected to the ICC by a skywalk.
* `Price` -- The total price, before taxes/fees. Essentially the nightly rate
times the number of nights.
* `Hotel` -- The name of the hotel.
* `Room` -- The description of the room. If the hotel has multiple rooms, there
will be multiple lines in the output. The number in parentheses is how many
rooms with that description are available.

## Usage

To fetch and run the script, open a terminal (Linux, Mac) / command prompt (Windows) and run:

```sh
git clone https://github.com/icirellik/gencon-hotel-check.git
cd gencon-hotel-check
python gencon-hotel-check.py
```

If you don't have git, you download it as a zip file.

`gencon-hotel-check.py --help` outputs the complete list of arguments, but these
are the most important:

* `--key` is the only mandatory argument, specifying your individual Passkey ID
number. You can find this via the [Gencon Housing](https://www.gencon.com/housing)
page. Click the "Go to Housing Portal" button and you will end up on a page with
a URL of the form `https://aws.passkey.com/reg/XXXXXXXX-XXXX/null/null/1/0/null`.
Pass `XXXXXXXX-XXXX` as the key argument to the script.
* `--checkin` and `--checkout` specify the date range you need. The default is
the days of the convention, Thursday through Sunday. Since Wednesday through
Sunday is also very common, you can use `--wednesday` as a shorthand.

## Alerts

Once a hotel is found, the script needs to alert you in some way. It will output
the matching hotel(s) with exclamation points next to them, but unless you're
looking at the terminal at the time that probably won't help. You can specify
any combination of the following options, multiple times each if necessary (e.g.
to e-mail multiple people).

### Run command

`gencon-hotel-check.py --cmd CMD`

Run the specified command, passing each hotel as a separate argument. This is
probably most useful on Linux. For example, passing the path to this script will
result in a libnotify popup:

```sh
#!/bin/bash
lines="$1"
shift
for i in "$@"; do
	lines="$lines\n$i"
done
notify-send -u critical "Gencon Hotel Alert" "$lines"
```

## Filtering

By default, the script looks for hotels near the ICC (where "near" means the
distance is measure in "blocks", not "miles") that have rooms available in the
date range you specified. There are a variety of optional arguments to narrow
this down further if necessary:

* `--max-distance` specifies the maximum blocks away the hotel can be. If 4
blocks is the farthest you want to walk, use `--max-distance 4`. If you require
a hotel connected to the ICC by a skywalk, use `--max-distance connected` (or
just `--connected`).
* `--budget` specifies the max amount you're willing to pay. This is the sum of
all the days (not just the daily rate), but does not include taxes or other
fees. This means if there's a $200/night room available Wednesday-Sunday, you
need a max budget of at least $800 to see it.
* `--hotel-regex` and `--room-regex` are [regular expressions](https://en.wikipedia.org/wiki/Regular_expression)
compared (case-insensitively) against the hotel name and room description.
Explaining regular expressions would take a while, but here are some likely
common cases:
  - To require that a particular value show up somewhere, just specify that
  value. To only show Marriott hotels: `--hotel-regex "marriott"`
  - To require one of a set of values show up, separate them with `|`. To only
  show hotels with double or queen beds: `--room-regex "double|queen"`
