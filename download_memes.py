"""Download real meme images from Slackmojis for ION chat."""

import urllib.request
from pathlib import Path

MEME_DIR = Path(__file__).parent / "src" / "ion" / "web" / "static" / "memes"
MEME_DIR.mkdir(parents=True, exist_ok=True)

# name -> (url, output_extension)
MEMES = {
    "this_is_fine": ("https://emojis.slackmojis.com/emojis/images/1643514545/5432/this-is-fine.gif", ".gif"),
    "this_is_fine_fire": ("https://emojis.slackmojis.com/emojis/images/1643514588/5906/this-is-fine-fire.gif", ".gif"),
    "lgtm": ("https://emojis.slackmojis.com/emojis/images/1647463888/56298/lgtm.png", ".png"),
    "ship_it": ("https://emojis.slackmojis.com/emojis/images/1643516254/22827/ship.png", ".png"),
    "facepalm": ("https://emojis.slackmojis.com/emojis/images/1643514046/51/facepalm.png", ".png"),
    "panic": ("https://emojis.slackmojis.com/emojis/images/1643514092/506/panic.gif", ".gif"),
    "mild_panic": ("https://emojis.slackmojis.com/emojis/images/1643515192/12068/mild-panic-intensifies.gif", ".gif"),
    "coffee": ("https://emojis.slackmojis.com/emojis/images/1643516222/22489/coffee_jitters.gif", ".gif"),
    "incident": ("https://emojis.slackmojis.com/emojis/images/1681849257/65272/incident-io.png", ".png"),
    "escalate": ("https://emojis.slackmojis.com/emojis/images/1666897766/62033/boy-that-escalated-quickly.png", ".png"),
    "nice_catch": ("https://emojis.slackmojis.com/emojis/images/1643514769/7802/nice.png", ".png"),
    "nailed_it": ("https://emojis.slackmojis.com/emojis/images/1649625921/57326/nailed_it.gif", ".gif"),
    "thinking": ("https://emojis.slackmojis.com/emojis/images/1643514509/4979/thinking.gif", ".gif"),
    "mind_blown": ("https://emojis.slackmojis.com/emojis/images/1643514098/559/mindblown.gif", ".gif"),
    "friday_deploy": ("https://emojis.slackmojis.com/emojis/images/1654275484/59489/friday.gif", ".gif"),
    "suspicious": ("https://emojis.slackmojis.com/emojis/images/1643514217/1835/suspicious.gif", ".gif"),
    "no_sleep": ("https://emojis.slackmojis.com/emojis/images/1693898076/68304/nosleep.jpg", ".jpg"),
    "threat_hunting": ("https://emojis.slackmojis.com/emojis/images/1643515527/15471/detective.gif", ".gif"),
    "partyparrot": ("https://emojis.slackmojis.com/emojis/images/1643514742/7500/partyparrot.gif", ".gif"),
    "dumpster_fire": ("https://emojis.slackmojis.com/emojis/images/1643514620/6248/dumpster-fire.gif", ".gif"),
    "deal_with_it": ("https://emojis.slackmojis.com/emojis/images/1643514086/439/deal_with_it.png", ".png"),
    "alert_fatigue": ("https://emojis.slackmojis.com/emojis/images/1643514064/204/facepalm.gif", ".gif"),
    # Extras from the first list
    "all_the_things": ("https://emojis.slackmojis.com/emojis/images/1643514043/23/all_the_things.jpg", ".jpg"),
    "doge": ("https://emojis.slackmojis.com/emojis/images/1643514075/312/doge.png", ".png"),
    "blinkingguy": ("https://emojis.slackmojis.com/emojis/images/1643514784/7942/blinkingguy.gif", ".gif"),
}


def main():
    print(f"Downloading {len(MEMES)} memes to {MEME_DIR}...")
    ok = 0
    fail = 0
    for name, (url, ext) in MEMES.items():
        out = MEME_DIR / f"{name}{ext}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ION-MemeDownloader/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read()
            out.write_bytes(data)
            print(f"  OK  {name}{ext} ({len(data)} bytes)")
            ok += 1
        except Exception as e:
            print(f"  FAIL {name}: {e}")
            fail += 1

    print(f"\nDone: {ok} downloaded, {fail} failed")


if __name__ == "__main__":
    main()
