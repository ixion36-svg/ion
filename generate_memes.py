"""Generate high-quality meme images for ION chat.

Downloads Twemoji PNGs and composites them with text overlays using Pillow.
"""

import io
import urllib.request
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter

MEME_DIR = Path(__file__).parent / "src" / "ion" / "web" / "static" / "memes"
MEME_DIR.mkdir(parents=True, exist_ok=True)

# Fonts
IMPACT = "C:/Windows/Fonts/impact.ttf"
BOLD = "C:/Windows/Fonts/arialbd.ttf"
SEGOE_EMOJI = "C:/Windows/Fonts/seguiemj.ttf"

# Twemoji CDN (CC-BY 4.0 license)
TWEMOJI_URL = "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72/{}.png"

# Emoji codepoints
EMOJI_CODES = {
    "fire": "1f525",
    "check": "2705",
    "rocket": "1f680",
    "facepalm": "1f926",
    "bell": "1f514",
    "eyeroll": "1f644",
    "raised_eyebrow": "1f928",
    "coffee": "2615",
    "scream": "1f631",
    "muscle": "1f4aa",
    "thinking": "1f914",
    "exploding_head": "1f92f",
    "skull": "1f480",
    "up_arrow": "2b06",
    "siren": "1f6a8",
    "bullseye": "1f3af",
    "sleeping": "1f634",
    "bandage": "1fa79",
    "magnifying": "1f50d",
    "gamepad": "1f3ae",
    "sunglasses": "1f60e",
    "salute": "1fae1",
    "pray": "1f64f",
}


def download_emoji(code):
    """Download a Twemoji PNG, return as PIL Image."""
    url = TWEMOJI_URL.format(code)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ION-MemeGenerator/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
        return Image.open(io.BytesIO(data)).convert("RGBA")
    except Exception as e:
        print(f"  Failed to download emoji {code}: {e}")
        return None


def create_meme(name, emoji_code, text_lines, bg_color, text_color=(255, 255, 255)):
    """Create a meme image: emoji on top, bold text below, colored background."""
    size = 128
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Rounded rectangle background
    r = 16
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=r, fill=bg_color)

    # Download and paste emoji
    emoji_img = download_emoji(emoji_code) if emoji_code else None
    if emoji_img:
        emoji_size = 52 if text_lines else 72
        emoji_img = emoji_img.resize((emoji_size, emoji_size), Image.LANCZOS)
        y_offset = 8 if text_lines else (size - emoji_size) // 2
        x_offset = (size - emoji_size) // 2
        img.paste(emoji_img, (x_offset, y_offset), emoji_img)

    # Draw text
    if text_lines:
        try:
            font = ImageFont.truetype(IMPACT, 16)
        except Exception:
            font = ImageFont.load_default()

        y_start = 66
        line_height = 20
        for i, line in enumerate(text_lines):
            bbox = draw.textbbox((0, 0), line, font=font)
            text_width = bbox[2] - bbox[0]
            x = (size - text_width) // 2
            y = y_start + i * line_height

            # Text shadow for readability
            draw.text((x + 1, y + 1), line, fill=(0, 0, 0, 160), font=font)
            draw.text((x, y), line, fill=text_color, font=font)

    # Save as PNG
    out_path = MEME_DIR / f"{name}.png"
    img.save(out_path, "PNG", optimize=True)
    print(f"  Created: {name}.png")
    return out_path


def create_emoji_only(name, emoji_code, bg_color):
    """Create a simple emoji-on-background meme."""
    return create_meme(name, emoji_code, [], bg_color)


def main():
    print("Generating ION meme pack...")
    print()

    # --- Emoji + Text combos ---
    print("Creating emoji + text memes:")
    create_meme("this_is_fine", "1f525", ["THIS IS", "FINE"], (200, 60, 20))
    create_meme("lgtm", "2705", ["LGTM"], (40, 160, 60))
    create_meme("ship_it", "1f680", ["SHIP IT"], (50, 120, 220))
    create_meme("alert_fatigue", "1f514", ["ALERT", "FATIGUE"], (180, 30, 30))
    create_meme("false_positive", "1f644", ["FALSE", "POSITIVE"], (180, 130, 20))
    create_meme("panic", "1f631", ["PANIC"], (220, 50, 50))
    create_meme("nailed_it", "1f4aa", ["NAILED IT"], (30, 120, 40))
    create_meme("friday_deploy", "1f480", ["FRIDAY", "DEPLOY"], (140, 20, 20))
    create_meme("escalate", "2b06", ["ESCALATE"], (210, 110, 40))
    create_meme("incident", "1f6a8", ["INCIDENT"], (200, 30, 30))
    create_meme("nice_catch", "1f3af", ["NICE", "CATCH"], (20, 110, 40))
    create_meme("no_sleep", "1f634", ["NO SLEEP"], (40, 45, 55))
    create_meme("patched", "1fa79", ["PATCHED"], (30, 120, 45))
    create_meme("threat_hunting", "1f50d", ["THREAT", "HUNTING"], (10, 15, 25), text_color=(0, 220, 255))
    create_meme("gg", "1f3ae", ["GG"], (60, 100, 200))

    # --- Emoji-only (large centered emoji) ---
    print()
    print("Creating emoji-only memes:")
    create_emoji_only("facepalm", "1f926", (55, 60, 70))
    create_emoji_only("suspicious", "1f928", (80, 45, 150))
    create_emoji_only("coffee", "2615", (100, 75, 15))
    create_emoji_only("thinking", "1f914", (25, 90, 200))
    create_emoji_only("mind_blown", "1f92f", (100, 55, 170))

    print()
    print(f"Done! {len(list(MEME_DIR.glob('*.png')))} PNG memes in {MEME_DIR}")


if __name__ == "__main__":
    main()
