# bot list taken from https://github.com/matomo-org/device-detector/blob/master/regexes/bots.yml
# the last two entries from that list were removed since they did not work well with Python's regex
# library.
botua = [
    r"synthetic-monitoring-agent.*",
    r"monitoring360bot",
    r"Cloudflare-Healthchecks",
    r"360Spider",
    r"Aboundex",
    r"AcoonBot",
    r"AddThis\.com",
    r"AhrefsBot",
    r"AhrefsSiteAudit/[\d.]+",
    r"ia_archiver|alexabot|verifybot",
    r"alexa site audit",
    r"Amazonbot/[\d.]+",
    r"AmazonAdBot/[\d.]+",
    r"Amazon[ -]Route ?53[ -]Health[ -]Check[ -]Service",
    r"AmorankSpider",
    r"ApacheBench",
    r"Applebot",
    r"AppSignalBot",
    r"Arachni",
    r"AspiegelBot",
    r"Castro 2, Episode Duration Lookup",
    r"Curious George",
    r"archive\.org_bot|special_archiver",
    r"Ask Jeeves/Teoma",
    r"Backlink-Check\.de",
    r"BacklinkCrawler",
    r"Baidu.*spider|baidu Transcoder",
    r"BazQux",
    r"Better Uptime Bot",
    r"MSNBot|msrbot|bingbot|bingadsbot|BingPreview|msnbot-(UDiscovery|NewsBlogs)|adidxbot",
    r"Blekkobot",
    r"BLEXBot",
    r"Bloglovin",
    r"Blogtrottr",
    r"BoardReader Blog Indexer",
    r"BountiiBot",
    r"Browsershots",
    r"BUbiNG",
    r"(?<!HTC)[ _]Butterfly/",
    r"CareerBot",
    r"CCBot",
    r"Cliqzbot",
    r"Cloudflare-AMP",
    r"Cloudflare-?Diagnostics",
    r"CloudFlare-AlwaysOnline",
    r"Cloudflare-SSLDetector",
    r"Cloudflare Custom Hostname Verification",
    r"Cloudflare-Traffic-Manager",
    r"https://developers\.cloudflare\.com/security-center/",
    r"coccoc\.com",
    r"collectd",
    r"CommaFeed",
    r"CSS Certificate Spider",
    r"Datadog Agent|Datadog/?Synthetics",
    r"Datanyze",
    r"Dataprovider",
    r"Daum(?!(?:Apps|Device))",
    r"Dazoobot",
    r"discobot",
    r"Domain Re-Animator Bot|support@domainreanimator\.com",
    r"DotBot",
    r"DuckDuck(?:Go-Favicons-)?Bot",
    r"EasouSpider",
    r"eCairn-Grabber",
    r"EMail Exractor",
    r"evc-batch",
    r"Exabot|ExaleadCloudview",
    r"ExactSeek Crawler",
    r"Ezooms",
    r"facebookexternalhit|facebookplatform|facebookexternalua|facebookcatalog",
    r"FacebookBot/[\d.]+",
    r"Feedbin",
    r"FeedBurner",
    r"Feed Wrangler",
    r"Feedly",
    r"Feedspot",
    r"Fever/[0-9]",
    r"FlipboardProxy|FlipboardRSS",
    r"Findxbot",
    r"FreshRSS",
    r"Genieo",
    r"GigablastOpenSource",
    r"Gluten Free Crawler",
    r"gobuster",
    r"ichiro/mobile goo",
    r"Storebot-Google",
    r"Google Favicon",
    r"Google Search Console",
    r"Google Page Speed Insights",
    r"google_partner_monitoring",
    r"Google-Cloud-Scheduler",
    r"Google-Structured-Data-Testing-Tool",
    r"GoogleStackdriverMonitoring",
    r"Google-Transparency-Report",
    r"via ggpht\.com GoogleImageProxy",
    r"SeznamEmailProxy",
    r"Seznam-Zbozi-robot",
    r"Heurekabot-Feed",
    r"ShopAlike",
    r"Adwords-(?:DisplayAds|Express|Instant)|Google Web Preview|Google[ -]Publisher[ -]Plugin|Google-(?:Ads-Conversions|Ads-Qualify|Adwords|AMPHTML|Assess|Extended|HotelAdsVerifier|InspectionTool|Lens|PageRenderer|Read-Aloud|Safety|Shopping-Quality|Site-Verification|speakr|Stale-Content-Probe|Test|Youtube-Links)|(?:AdsBot|APIs|DuplexWeb|Feedfetcher|Mediapartners)-Google(?:-Mobile)?|Google(?:AdSenseInfeed|AssociationService|bot|Other|Prober|Producer)|Google.*/\+/web/snippet",
    r"^Google$",
    r"Google-Area120-PrivacyPolicyFetcher",
    r"heritrix",
    r"HubSpot ",
    r"vuhuvBot",
    r"HTTPMon/[\d.]+",
    r"ICC-Crawler",
    r"inoreader\.com",
    r"iisbot",
    r"ips-agent",
    r"IP-Guide\.com",
    r"k6/[0-9\.]+",
    r"kouio",
    r"larbin",
    r"[A-z0-9]*-Lighthouse",
    r"last-modified\.com",
    r"linkdexbot|linkdex\.com",
    r"LinkedInBot",
    r"ltx71",
    r"Mail\.RU",
    r"magpie-crawler",
    r"MagpieRSS",
    r"masscan-ng/[\d.]+",
    r"masscan",
    r"Mastodon/",
    r"meanpathbot",
    r"MetaJobBot",
    r"MetaInspector",
    r"MixrankBot",
    r"MJ12bot",
    r"Mnogosearch",
    r"MojeekBot",
    r"munin",
    r"NalezenCzBot",
    r"check_http/v",
    r"nbertaupete95\(at\)gmail\.com",
    r"Netcraft(?: Web Server Survey| SSL Server Survey|SurveyAgent)",
    r"netEstate NE Crawler",
    r"Netvibes",
    r"NewsBlur .*(?:Fetcher|Finder)",
    r"NewsGatorOnline",
    r"nlcrawler",
    r"Nmap Scripting Engine",
    r"Nuzzel",
    r"Octopus [0-9]",
    r"OnlineOrNot\.com_bot",
    r"omgili",
    r"OpenindexSpider",
    r"spbot",
    r"OpenWebSpider",
    r"OrangeBot|VoilaBot",
    r"PaperLiBot",
    r"phantomas/",
    r"phpservermon",
    r"Pocket(?:ImageCache|Parser)/[\d.]+",
    r"PritTorrent",
    r"PRTG Network Monitor",
    r"psbot",
    r"Pingdom(?:\.com|TMS)",
    r"Quora Link Preview",
    r"Quora-Bot",
    r"RamblerMail",
    r"QuerySeekerSpider",
    r"Qwantify",
    r"Rainmeter",
    r"redditbot",
    r"Riddler",
    r"rogerbot",
    r"ROI Hunter",
    r"SafeDNSBot",
    r"Scrapy",
    r"Screaming Frog SEO Spider",
    r"ScreenerBot",
    r"SemrushBot",
    r"SerpReputationManagementAgent/[\d.]+",
    r"SplitSignalBot",
    r"SiteAuditBot/[\d.]+",
    r"SensikaBot",
    r"SEOENG(?:World)?Bot",
    r"SEOkicks-Robot",
    r"seoscanners\.net",
    r"SkypeUriPreview",
    r"SeznamBot|SklikBot|Seznam screenshot-generator",
    r"shopify-partner-homepage-scraper",
    r"ShopWiki",
    r"SilverReader",
    r"SimplePie",
    r"SISTRIX Crawler",
    r"compatible; (?:SISTRIX )?Optimizer",
    r"SiteSucker",
    r"sixy\.ch",
    r"Slackbot|Slack-ImgProxy",
    r"Sogou[ -](?:head|inst|Orion|Pic|Test|web)[ -]spider|New-Sogou-Spider",
    r"Sosospider|Sosoimagespider",
    r"Sprinklr",
    r"sqlmap/",
    r"SSL Labs",
    r"StatusCake",
    r"Superfeedr bot",
    r"Sparkler/[0-9]",
    r"Spinn3r",
    r"SputnikBot",
    r"SputnikFaviconBot",
    r"SputnikImageBot",
    r"SurveyBot",
    r"TarmotGezgin",
    r"TelegramBot",
    r"TLSProbe",
    r"TinEye-bot",
    r"Tiny Tiny RSS",
    r"theoldreader\.com",
    r"Trackable/0.1",
    r"trendictionbot",
    r"TurnitinBot",
    r"TweetedTimes",
    r"TweetmemeBot",
    r"Twingly Recon",
    r"Twitterbot",
    r"UniversalFeedParser",
    r"via secureurl\.fwdcdn\.com",
    r"Uptimebot",
    r"UptimeRobot",
    r"URLAppendBot",
    r"Vagabondo",
    r"vkShare; ",
    r"VKRobot",
    r"VSMCrawler",
    r"Jigsaw",
    r"W3C_I18n-Checker",
    r"W3C-checklink",
    r"W3C_Validator|Validator\.nu",
    r"W3C-mobileOK",
    r"W3C_Unicorn",
    r"P3P Validator",
    r"Wappalyzer",
    r"PTST/",
    r"WeSEE",
    r"WebbCrawler",
    r"websitepulse[+ ]checker",
    r"WordPress.+isitwp\.com",
    r"Automattic Analytics Crawler/[\d.]+",
    r"WordPress",
    r"Wotbox",
    r"XenForo",
    r"yacybot",
    r"Yahoo! Slurp|Yahoo!-AdCrawler",
    r"Yahoo Link Preview|Yahoo:LinkExpander:Slingstone",
    r"YahooMailProxy",
    r"YahooCacheSystem",
    r"Y!J-BRW",
    r"Y!J-WSC",
    r"Yandex(?:(?:\.Gazeta |Accessibility|Mobile|MobileScreenShot|RenderResources|Screenshot|Sprav)?Bot|(?:AdNet|Antivirus|Blogs|Calendar|Catalog|Direct|Favicons|ForDomain|ImageResizer|Images|Market|Media|Metrika|News|OntoDB(?:API)?|Pagechecker|Partner|RCA|SearchShop|(?:News|Site)links|Tracker|Turbo|Userproxy|Verticals|Vertis|Video|Webmaster))|YaDirectFetcher",
    r"Yeti|NaverJapan|AdsBot-Naver",
    r"YoudaoBot",
    r"YOURLS v[0-9]",
    r"YRSpider|YYSpider",
    r"zgrab",
    r"Zookabot",
    r"ZumBot",
    r"YottaaMonitor",
    r"Yahoo Ad monitoring.*yahoo-ad-monitoring-SLN24857",
    r".*Java.*outbrain",
    r"HubPages.*crawlingpolicy",
    r"Pinterest(?:bot)?/[\d.]+.*www\.pinterest\.com",
    r".*Site24x7",
    r".* HLB/[\d.]+",
    r"s~snapchat-proxy",
    r"Snap URL Preview Service",
    r"SnapchatAds/[\d.]+",
    r"Let's Encrypt validation server",
    r"GrapeshotCrawler",
    r"www\.monitor\.us",
    r"Catchpoint",
    r"bitlybot",
    r"Zao/",
    r"lycos",
    r"Slurp",
    r"Speedy Spider",
    r"ScoutJet",
    r"nrsbot|netresearch",
    r"scooter",
    r"gigabot",
    r"charlotte",
    r"Pompos",
    r"ichiro",
    r"PagePeeker",
    r"WebThumbnail",
    r"Willow Internet Crawler",
    r"EmailWolf",
    r"NetLyzer FastProbe",
    r"AdMantX.*admantx\.com",
    r"Server Density Service Monitoring",
    r"RSSRadio \(Push Notification Scanner;support@dorada\.co\.uk\)",
    r"^sentry",
    r"^Spotify/[\d.]+$",
    r"The Knowledge AI",
    r"Embedly",
    r"BrandVerity",
    r"Kaspersky Lab CFR link resolver",
    r"eZ Publish Link Validator",
    r"woorankreview",
    r"by Siteimprove\.com",
    r"CATExplorador",
    r"Buck",
    r"tracemyfile",
    r"zelist\.ro feed parser",
    r"weborama-fetcher",
    r"BoardReader Favicon Fetcher",
    r"IDG/IT",
    r"Bytespider",
    r"WikiDo",
    r"Awario(?:Smart)?Bot",
    r"AwarioRssBot",
    r"oBot",
    r"SMTBot",
    r"LCC",
    r"Startpagina-Linkchecker",
    r"MoodleBot-Linkchecker",
    r"GTmetrix",
    r"Nutch",
    r"Seobility",
    r"Vercelbot",
    r"Grammarly",
    r"Robozilla",
    r"Domains Project",
    r"PetalBot",
    r"SerendeputyBot",
    r"ias-(?:va|sg).*admantx.*service-fetcher|admantx\.com.*service-fetcher",
    r"SemanticScholarBot",
    r"VelenPublicWebCrawler",
    r"Barkrowler",
    r"BDCbot",
    r"adbeat",
    r"BW/[\d.]+",
    r"https://whatis\.contentkingapp\.com",
    r"MicroAdBot",
    r"PingAdmin\.Ru",
    r"notifyninja.+monitoring",
    r"WebDataStats",
    r"parse\.ly scraper",
    r"Nimbostratus-Bot",
    r"HeartRails_Capture/[\d.]+",
    r"Project-Resonance",
    r"DataXu/[\d.]+",
    r"Cocolyzebot",
    r"veryhip",
    r"LinkpadBot",
    r"MuscatFerret",
    r"PageThing\.com",
    r"ArchiveBox",
    r"Choosito",
    r"datagnionbot",
    r"WhatCMS",
    r"httpx",
    r"scaninfo@(?:expanseinc|paloaltonetworks)\.com",
    r"HuaweiWebCatBot",
    r"Hatena-Favicon",
    r"Hatena-?Bookmark",
    r"RyowlEngine/[\d.]+",
    r"OdklBot/[\d.]+",
    r"Mediatoolkitbot",
    r"ZoominfoBot",
    r"WeViKaBot/[\d.]+",
    r"SEOkicks",
    r"Plukkie/[\d.]+",
    r"proximic;",
    r"SurdotlyBot/[\d.]+",
    r"Gowikibot/[\d.]+",
    r"SabsimBot/[\d.]+",
    r"LumtelBot/[\d.]+",
    r"PiplBot",
    r"woobot/[\d.]+",
    r"Cookiebot/[\d.]+",
    r"NetSystemsResearch",
    r"CensysInspect/[\d.]+",
    r"gdnplus\.com",
    r"WellKnownBot/[\d.]+",
    r"Adsbot/[\d.]+",
    r"MTRobot/[\d.]+",
    r"serpstatbot/[\d.]+",
    r"colly",
    r"l9tcpid/v[\d.]+",
    r"l9explore/[\d.]+",
    r"l9scan/|^Lkx-.*/[\d.]+",
    r"MegaIndex\.ru/[\d.]+",
    r"Seekport",
    r"seolyt/[\d.]+",
    r"YaK/[\d.]+",
    r"KomodiaBot/[\d.]+",
    r"Neevabot/[\d.]+",
    r"LinkPreview/[\d.]+",
    r"JungleKeyThumbnail/[\d.]+",
    r"rocketmonitor(?: |bot/)[\d.]+",
    r"SitemapParser-VIPnytt/[\d.]+",
    r"^Turnitin",
    r"DMBrowser/[\d.]+|DMBrowser-[UB]V",
    r"ThinkChaos/",
    r"DataForSeoBot",
    r"Discordbot/[\d.]+",
    r"Linespider/[\d.]+",
    r"Cincraw/[\d.]+",
    r"CISPA Web Analyzer",
    r"IonCrawl",
    r"Crawldad",
    r"https://securitytxt-scan\.cs\.hm\.edu/",
    r"TigerBot/[\d.]+",
    r"TestCrawler/[\d.]+",
    r"CrowdTanglebot/[\d.]+",
    r"Sellers\.Guide Crawler by Primis",
    r"OnalyticaBot",
    r"deepnoc",
    r"Newslitbot/[\d.]+",
    r"um-LN/[\d.]+",
    r"Abonti/[\d.]+",
    r"collection@infegy\.com",
    r"HTTP Banner Detection \(https://security\.ipip\.net\)",
    r"ev-crawler/[\d.]+",
    r"webprosbot/[\d.]+",
    r"ELB-HealthChecker",
    r"Wheregoes\.com Redirect Checker/[\d.]+",
    r"project_patchwatch",
    r"InternetMeasurement/[\d.]+",
    r"DomainAppender /[\d.]+",
    r"FreeWebMonitoring SiteChecker/[\d.]+",
    r"Page Modified Pinger",
    r"adstxtlab\.com",
    r"Iframely/[\d.]+",
    r"DomainStatsBot/[\d.]+",
    r"aiHitBot/[\d.]+",
    r"DomainCrawler/",
    r"DNSResearchBot",
    r"GitCrawlerBot",
    r"AdAuth/[\d.]+",
    r"faveeo\.com",
    r"kozmonavt\.",
    r"CriteoBot/",
    r"PayPal IPN",
    r"MaCoCu",
    r"dnt-policy@eff\.org",
    r"InfoTigerBot",
    r"(?:Birdcrawlerbot|CrawlaDeBot)",
    r"ScamadviserExternalHit/[\d.]+",
    r"ZaldamoSearchBot",
    r"AFB/[\d.]+",
    r"SeolytBot/[\d.]+",
    r"LinkWalker/[\d.]+",
    r"RenovateBot/[\d.]+",
    r"INETDEX-BOT/[\d.]+",
    r"NETZZAPPEN",
    r"panscient\.com",
    r"research@pdrlabs\.net",
    r"Nicecrawler/[\d.]+",
    r"t3versionsBot/[\d.]+",
    r"Crawlson/[\d.]+",
    r"tchelebi/[\d.]+",
    r"JobboerseBot",
    r"RepoLookoutBot/v?[\d.]+",
    r"PATHspider",
    r"everyfeed-spider/[\d.]+",
    r"Exchange check",
    r"Sublinq",
    r"Gregarius/[\d.]+",
    r"COMODO DCV",
    r"Sectigo DCV",
    r"KlarnaBot-(?:DownloadProductImage|EnrichProducts|PriceWatcher)/[\d.]+",
    r"Taboolabot/[\d.]+",
    r"Asana/[\d.]+",
    r"Chrome Privacy Preserving Prefetch Proxy",
    r"URLinspectorBot/[\d.]+",
    r"EntferBot/[\d.]+",
    r"TagInspector/[\d.]+",
    r"pageburst",
    r".+diffbot",
    r"DisqusAdstxtCrawler/[\d.]+",
    r"startmebot/[\d.]+",
    r"2ip bot/[\d.]+",
    r"ReqBin Curl Client/[\d.]+",
    r"XoviBot/[\d.]+",
    r"Overcast/[\d.]+ Podcast Sync",
    r"^Verity/[\d.]+",
    r"hackermention",
    r"BitSightBot/[\d.]+",
    r"Ezgif/[\d.]+",
    r"intelx\.io_bot",
    r"FemtosearchBot/[\d.]+",
    r"AdsTxtCrawler/[\d.]+",
    r"Morningscore",
    r"Uptime-Kuma/[\d.]+",
    r"ChatGPT-User",
    r"BrightEdge Crawler/[\d.]+",
    r"sfFeedReader/[\d.]+",
    r"cyberscan\.io",
    r"deepcrawl\.com",
    r"researchscan\.comsys\.rwth-aachen\.de",
    r"newspaper/[\d.]+",
    r"GPTBot/[\d.]+",
    r"Ant(?:\.com beta|Bot)(?:/([\d+.]+))?",
    r"WebwikiBot/[\d.]+",
    r"phpMyAdmin",
    r"Matomo/[\d.]+",
    r"Prometheus/[\d.]+",
    r"ArchiveTeam ArchiveBot",
    r"MADBbot/[\d.]+",
    r"MeltwaterNews",
    r"(?:Owler@ows\.eu|OWLer)/[\d.]+",
    r"bbc\.co\.uk/display/men/Page\+Monitor",
    r"BBC-Forge-URL-Monitor-Twisted",
    r"ClaudeBot",
    r"Imagesift",
    r"TactiScout",
    r"Brightbot ([\d+.]+)",
    r"DaspeedBot/([\d+.]+)",
    r"StractBot(?:/([\d+.]+))?",
    r"GeedoBot(?:/([\d+.]+))?",
    r"BackupLand(?:/([\d+.]+))?",
    r"Konturbot(?:/([\d+.]+))?",
    r"keys-so-bot",
    r"LetsearchBot(?:/([\d+.]+))?",
    r"Example3(?:/([\d+.]+))?",
    r"StatOnlineRuBot(?:/([\d+.]+))?",
    r"Spawning-AI",
    r"domain research project",
    r"getodin\.com",
    r"YouBot",
    r"SiteScoreBot",
    r"MBCrawler",
    r"mariadb-mysql-kbs-bot",
    r"GitHubCopilotChat",
    r"anthropic-ai",
    r"NetpeakCheckerBot/[\d.]+",
    r"SandobaCrawler/[\d.]+",
    r"SirdataBot",
    r"CheckMarkNetwork/[\d.]+",
    r"cohere-ai",
    r"PerplexityBot/[\d.]+",
    r"TTD-Content",
    r"montastic-monitor",
    r"Ruby, Twurly v[\d.]+",
    r"Mixnode(?:(?:Cache)?/[\d.]+)?",
    r"CSSCheck/[\d.]+",
    r"MicrosoftPreview/[\d.]+",
    r"s~virustotalcloud",
    r"TinEye/[\d.]+",
    r"e~arsnova-filter-system",
    r"botify",
    r"adscanner",
    r"online-webceo-bot/[\d.]+",
    r"NetTrack",
    r"htmlyse",
    r"TrendsmapResolver/[\d.]+",
    r"Shareaholic(?:bot)?/[\d.]+",
    r"keycdn-tools:",
    r"keycdn-tools/",
    r"Arquivo-web-crawler",
    r"WhatsMyIP\.org",
    r"SenutoBot/[\d.]+",
    r"spaziodati",
    r"GozleBot",
    r"Quantcastbot/[\d.]+",
    r"FontRadar",
    r"ViberUrlDownloader",
    r"^Zeno$",
    r"Barracuda Sentinel",
    r"RuxitSynthetic/[\d.]+",
    r"DynatraceSynthetic/[\d.]+",
    r"sitebulb",
    r"Monsidobot/[\d.]+",
    r"AccompanyBot",
    r"Ghost Inspector",
    r"Cypress/[\d.]+",
    r"Google-Apps-Script",
    r"SiteOne-Crawler/[\d.]+",
    r"Detectify",
    r"DomCopBot",
    r"Paqlebot/[\d.]+",
    r"Wibybot",
    r"Synapse",
    r"OSZKbot/[\d.]+",
    r"ZoomBot",
    r"RavenCrawler/[\d.]+",
    r"KadoBot",
    r"Dubbotbot/[\d.]+",
    r"Swiftbot/[\d.]+",
    r"EyeMonIT",
    r"ThousandEyes",
    r"OmtrBot/[\d.]+",
    r"WebMon/[\d.]+",
    r"AdsTxtCrawlerTP/[\d.]+",
    r"fragFINN",
    r"Clickagy",
    r"kiwitcms-gitops/[\d.]+",
    # r"nuhk|grub-client|Download Demon|SearchExpress|Microsoft URL Control|borg|altavista|dataminr\.com|teoma|oegp|http%20client|htdig|mogimogi|larbin|scrubby|searchsight|semanticdiscovery|snappy|vortex(?!(?: Build|Plus))|zeal(?!ot)|dataparksearch|findlinks|BrowserMob|URL2PNG|ZooShot|GomezA|Google SketchUp|Read%20Later|7Siters|centuryb\.o\.t9|InterNaetBoten|EasyBib AutoCite|Bidtellect|tomnomnom/meg|cortex|Re-re Studio|adreview|AHC/|NameOfAgent|Request-Promise|ALittle Client|Hello,? world|wp_is_mobile|0xAbyssalDoesntExist|Anarchy99|^revolt|nvd0rz|xfa1|Hakai|gbrmss|fuck-your-hp|IDBTE4M CODE87|Antoine|Insomania|Hells-Net|b3astmode|Linux Gnu \(cow\)|Test Certificate Info|iplabel|Magellan|TheSafex?Internetx?Search|Searcherweb|kirkland-signature|^xenu|^ZmEu|^(?:chrome|firefox|Zeus)$",
    # r"[a-z0-9_-]*(?:(?<!cu|power[ _]|m[ _])bot(?![ _]TAB|[ _]?5[0-9]|[ _]Senior|[ _]Junior)|analyzer|appengine|archiver|checker|collector|crawl|crawler|fetcher|indexer|inspector|monitor|project(?!or)|(?<!Google Wap )proxy|research|resolver|robots|scraper|script|searcher|(?<!dapper-)security|spider|study|transcoder|uptime|user[ _]?agent|validator)(?:[^a-z]|$)",
]