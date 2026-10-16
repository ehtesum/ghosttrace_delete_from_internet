from checkers.base import BaseChecker


class DataBrokerChecker(BaseChecker):
    ID, NAME = "data_brokers", "Data Broker Exposure"
    PRIVACY, CATEGORY = "local", "privacy"
    LAYER = "deep"
    DELETE_URL = "https://www.privacyrights.org/data-brokers"

    BROKERS = [
        {"name": "Spokeo",        "url": "https://www.spokeo.com/optout",                          "type": "People Search"},
        {"name": "BeenVerified",  "url": "https://www.beenverified.com/app/optout/search",          "type": "Background Check"},
        {"name": "Whitepages",    "url": "https://www.whitepages.com/suppression_requests",         "type": "People Search"},
        {"name": "Intelius",      "url": "https://www.intelius.com/optout",                         "type": "Background Check"},
        {"name": "PeopleFinder",  "url": "https://www.peoplefinder.com/optout.php",                 "type": "People Search"},
        {"name": "Radaris",       "url": "https://radaris.com/control/privacy",                     "type": "People Search"},
        {"name": "US Search",     "url": "https://www.ussearch.com/opt-out/",                       "type": "Background Check"},
        {"name": "Pipl",          "url": "https://pipl.com/personal-information-removal-request",   "type": "People Search"},
        {"name": "Acxiom",        "url": "https://isapps.acxiom.com/optout/optout.aspx",            "type": "Data Aggregator"},
        {"name": "LexisNexis",    "url": "https://optout.lexisnexis.com/",                          "type": "Data Aggregator"},
        {"name": "Oracle",        "url": "https://datacloudoptout.oracle.com/",                     "type": "Data Aggregator"},
        {"name": "Epsilon",       "url": "https://us.epsilon.com/privacy-policy/opt-out",           "type": "Marketing"},
        {"name": "ZoomInfo",      "url": "https://www.zoominfo.com/about/privacy/consumer-opt-out", "type": "B2B Data"},
        {"name": "MyLife",        "url": "https://www.mylife.com/ccpa/index.pubview",               "type": "People Search"},
        {"name": "Instant Checkmate","url": "https://www.instantcheckmate.com/opt-out/",            "type": "Background Check"},
    ]

    def check(self):
        return self.found(
            f"{len(self.BROKERS)} known data brokers likely hold your information — opt-out links in data",
            data=self.BROKERS,
        )
