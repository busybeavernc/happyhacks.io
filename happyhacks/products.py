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
        "name": "Doppleganger",
        "tagline": "A seamless switch.",
        "description": (
            "Doppleganger records a short, seamless loop of you, then lets you switch between that loop and your live "
            "webcam in Zoom, Teams or any browser meeting. For Windows 10/11 and macOS 12+."
        ),
        "status": "Windows & Mac",
        "icon": "img/apps/doppleganger.png",
        "url": "https://github.com/busybeavernc/doppleganger/releases/latest",
        "cta": "Download",
    },
]


def get_product(slug: str):
    return next((p for p in PRODUCTS if p["slug"] == slug), None)
