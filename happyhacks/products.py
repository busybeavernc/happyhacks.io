"""Product catalog. Add a new Happy Hacks product by appending to PRODUCTS.

  icon   the app's own icon in static/img/apps/ (a square PNG, 192 px), shown on its card and page; None for none yet
  cta    the button on its page ("Open ZipZip", "Download"); url is where it goes
"""

PRODUCTS = [
    {
        "slug": "zipzip",
        "name": "ZipZip",
        "tagline": "A real-estate assistant for North Carolina listing agents.",
        "description": (
            "ZipZip helps agents move listings from first conversation to MLS-ready, "
            "including premade forms prepared for fast, accurate fill-in."
        ),
        "status": "In development",
        "icon": "img/apps/zipzip.png",
        "url": "https://zipzip.happyhacks.io",
        "cta": "Open ZipZip",
    },
    {
        "slug": "doppleganger",
        "name": "BRB",
        "tagline": "Need a moment? Be right back.",
        "description": (
            "BRB (Be Right Back) switches between your live camera and a short recorded loop of you, so you can take "
            "a quick break from a video meeting without distracting anyone. Works with the major meeting apps. "
            "For Windows 10/11 and macOS 12+."
        ),
        "status": "Windows & Mac",
        "icon": "img/apps/doppleganger.png",
        "url": "https://brb.happyhacks.io",
        "cta": "Get BRB",
    },
]


def get_product(slug: str):
    return next((p for p in PRODUCTS if p["slug"] == slug), None)
