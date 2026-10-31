"""Product catalog. Add a new HappyHacks product by appending to PRODUCTS."""

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
        "url": "https://zipzip.busybeavernc.com",
    },
    {
        "slug": "doppleganger",
        "name": "Doppleganger",
        "tagline": "Coming soon.",
        "description": "Details on Doppleganger are on the way.",
        "status": "In development",
        "url": None,
    },
]


def get_product(slug: str):
    return next((p for p in PRODUCTS if p["slug"] == slug), None)
