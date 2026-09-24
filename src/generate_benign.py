"""Generate benign prompts in the same genre as the attack corpora.

The corpora do not merely differ in intent, they differ in genre. AdvBench and
JailbreakBench are terse technical imperatives ("Write a script that...",
"Create a tutorial on..."), while Alpaca's benign half is general-knowledge
question answering. Nothing teaches the model that an imperative technical
request can be legitimate, so it learned the genre as the signal: "tutorial"
was 100% attack in the corpus, "code" 98%, "script" 96%.

Hand-written examples cannot balance a thousand attacks. These are generated
combinatorially so the same verbs, objects and sentence shapes appear on both
sides of the label.
"""
import itertools
import random

VERBS = ["Write", "Create", "Draft", "Build", "Generate", "Put together", "Design"]

SCRIPT_TASKS = [
    "a script to rename files in a folder by date",
    "a script that backs up a database every night",
    "a script to resize a batch of images",
    "a script that checks whether a website is up",
    "a script to merge several CSV files",
    "a script that archives logs older than 30 days",
    "a python script to plot sales data from a spreadsheet",
    "a bash script that rotates application logs",
    "a script to convert Markdown files into PDFs",
    "a script that syncs two folders",
    "a script to send a weekly summary email to the team",
    "a script that validates our config before deployment",
]

CODE_TASKS = [
    "code to reverse a linked list",
    "code that parses an ISO date string",
    "code to paginate results from an API",
    "code for a retry with exponential backoff",
    "code to read environment variables with defaults",
    "code that caches expensive function calls",
    "a function to deduplicate a list while keeping order",
    "unit tests for a shopping cart class",
    "a SQL query to find the top ten customers by revenue",
    "a regular expression that matches UK postcodes",
]

GUIDE_TASKS = [
    "a guide for new joiners on setting up their laptop",
    "a guide to our code review process",
    "a tutorial on using Git branches",
    "a tutorial explaining how REST APIs work",
    "a guide to deploying a Flask application",
    "a tutorial on writing good commit messages",
    "a guide to reading a balance sheet",
    "a tutorial for beginners on using spreadsheets",
    "a guide to preparing for a technical interview",
    "a tutorial on making filter coffee",
]

CONTENT_TASKS = [
    "an email to my manager about my leave request",
    "an email to a client about a delayed delivery",
    "a message to reschedule tomorrow's meeting",
    "a message congratulating a colleague on their promotion",
    "a cover letter for a data analyst role",
    "a letter of recommendation for a student",
    "a blog post about remote working",
    "a social media post announcing our product launch",
    "a product description for an online shop",
    "a profile summary for my CV",
    "a website landing page for a small bakery",
    "an announcement about our office move",
]

SUFFIXES = ["", ".", " please.", " for me", " in Python", " step by step",
            " for a beginner", " using simple language"]


def generate(limit: int = 420, seed: int = 42) -> list[str]:
    random.seed(seed)
    pools = [SCRIPT_TASKS, CODE_TASKS, GUIDE_TASKS, CONTENT_TASKS]
    combos = [
        f"{verb} {task}{suffix}".strip()
        for pool in pools
        for verb, task in itertools.product(VERBS, pool)
        for suffix in random.sample(SUFFIXES, 2)
    ]
    # Deduplicate while keeping variety, then sample down to the requested size.
    unique = list(dict.fromkeys(combos))
    random.shuffle(unique)
    return unique[:limit]


if __name__ == "__main__":
    rows = generate()
    print(f"{len(rows)} generated. Sample:")
    for r in rows[:8]:
        print("  -", r)
