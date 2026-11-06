# Подборка вредоносных APK с вердиктами вендоров

Всего образцов: **2000**, с отчётом VirusTotal: **137**, с разбором вложенных файлов: **135**.

Источники: MalwareBazaar (abuse.ch) API, VirusTotal API v3. Образцы не скачивались.

Файлы: `apk_verdicts.csv` (образец на строку), `apk_verdicts_long.csv` (все вендоры), `apk_inner_files.csv` (вредоносные файлы внутри APK), `apk_verdicts.json` (всё).

## Семейства (по MalwareBazaar)

| Семейство | Кол-во |
|---|---|
| n/a | 608 |
| IRATA | 171 |
| SpyNote | 170 |
| Cerberus | 169 |
| Hydra | 152 |
| Coper | 114 |
| Triada | 94 |
| Alien | 92 |
| Joker | 75 |
| BRATA | 31 |
| BankBot | 30 |
| Anubis | 29 |
| FluBot | 27 |
| SharkBot | 26 |
| Ermac | 25 |
| Hook | 25 |
| AhMyth | 13 |
| Sova | 12 |
| GodFather | 10 |
| PixRevolution | 10 |
| TeaBot | 10 |
| Octo | 9 |
| Vultur | 9 |
| Copybara | 8 |
| TgToxic | 7 |
| Crocodilus | 6 |
| Mirai | 6 |
| SpyMax | 5 |
| Harly | 4 |
| JackSkid | 4 |
| AndroRAT | 3 |
| BingoMod | 3 |
| CECbot | 3 |
| Chameleon | 3 |
| Metasploit | 3 |
| NGate | 3 |
| SilentNet | 3 |
| Teabot | 3 |
| Ahmyth | 2 |
| Albiriox | 2 |

## Покрытие вердиктами

| Источник | Образцов |
|---|---|
| VirusTotal (~70 AV) | 137 |
| ReversingLabs (через MalwareBazaar) | 1996 |
| Triage (через MalwareBazaar) | 1963 |
| CERT-PL_MWDB (через MalwareBazaar) | 1735 |
| FileScan-IO (через MalwareBazaar) | 1700 |
| Spamhaus_HBL (через MalwareBazaar) | 1543 |
| InQuest (через MalwareBazaar) | 1525 |
| YOROI_YOMI (через MalwareBazaar) | 1497 |
| Kaspersky (через MalwareBazaar) | 794 |
| vxCube (через MalwareBazaar) | 7 |
| DocGuard (через MalwareBazaar) | 1 |
| CAPE (через MalwareBazaar) | 1 |
| YARA (MalwareBazaar) | 1021 |

## Пример: вердикты MalwareBazaar-вендоров (по 2 образца на семейство)

| SHA-256 | Семейство | ReversingLabs | RL сканеры | Kaspersky | FileScan | Triage |
|---|---|---|---|---|---|---|
| `bfc577ea1b9b326609d857e0c7ea4c7db5c382f86b3faeb92e9230da650b3af9` | AhMyth | Android.Trojan.Ahmyth | 15/38 | Malware |  | ahmyth score=10 |
| `cdd0d2e6639bfb11299b168748c77bced8821075c6cb04ed4b1f888a369228fd` | Ahmyth | Android.Trojan.Ahmyth | 11/24 | Malware |  | ahmyth score=10 |
| `8b5cfe53c6b30897bed06d794d73c0bb499620ca1e0128f18b1ae91a197d8548` | Ajina | Android.Trojan.Generic | 7/35 |  | MALICIOUS | ajina score=10 |
| `8703ee8685a47d4085b737b29aaa0f6f7898985b41963bd15d7027c75a609a3e` | Albiriox | KNOWN | 2/23 | Malware | MALICIOUS | score=7 |
| `39ccc5d7009aefac18891c70a16b857b98481d6f69800075e31900c4dc9ef000` | Alien | Android.Dropper.Hqwar | 9/25 |  | MALICIOUS | alienbot score=10 |
| `c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103` | AndroRAT | Android.Trojan.SpyAgent | 11/23 | Malware | LIKELY_MALICIOUS | androrat score=10 |
| `d17d2f0ab340d52c83e59d3d7d6636d92e15f23a9a70b4f402c5af54cfc291af` | Anubis | Android.Infostealer.Anubis | 7/23 | Malware | MALICIOUS | score=6 |
| `1430dc0cc26adfb7b7715624602767af26f453e3f34df66f1a6d41c38a35819c` | BRATA | Android.Trojan.SpyNote | 15/41 |  | MALICIOUS | brata score=10 |
| `8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4` | BankBot | Android.Infostealer.Anubis | 12/24 | Malware | LIKELY_MALICIOUS | score=6 |
| `a769c40ce48a38eed8897447081fc002d567535943befc4b51d866d134953588` | BingoMod | KNOWN | 3/24 |  | LIKELY_MALICIOUS | bingomod score=10 |
| `a25bf4bdb2ed9872456af0057eb21ce31fd03d680d63a9da469519060b4814bc` | BlackRock | Android.Spyware.Flubot | 9/23 |  | MALICIOUS | score=8 |
| `1f333d910158316c6211f7b24d118aadca778abb3964f3a4b7d3914e49278b7d` | BtmobRAT | Linux.Trojan.BitCoinMi | 24/36 | Malware |  | btmobrat score=10 |
| `a9859c49d20baf131d1e9253acb0118fac412acaa97938d87c7c8daa7554cd54` | CECbot | Linux.Worm.Mirai | 15/38 | Malware | MALICIOUS | cecbot score=10 |
| `a52d2105d680d029f9cc5c9c77f639e47ae520e41ce7294bbad77b8f2931796a` | Cerberus | Android.Infostealer.Banbra | 11/38 |  |  | cerberus score=10 |
| `b8ea74902684dcced62a5ca2c1d6932659decfefcbdb2615bfe5899e05eb1451` | Chameleon | Android.Trojan.Generic | 9/38 |  | SUSPICIOUS | chameleon score=10 |
| `0628ad6d1fd836b13b22e75fa169502d8ce78b7ad20f0261eb5151da98437bca` | CoinMiner | Linux.Coinminer.Generic | 16/24 | Malware | MALICIOUS | xmrig score=10 |
| `841e432a41b9625040704fd636d4fc3814a6d4193fa315cd78cfed9aa3991c04` | Coper | Android.Trojan.BankerAgent | 9/24 | Malware | MALICIOUS | octo score=10 |
| `464fee5a6d85370e8764f0e682ef01cf2d9cef3efb7e4bbdf0146a94cc83ff4a` | Copybara | KNOWN | 5/36 | Malware | MALICIOUS | copybara score=10 |
| `5f94e59c132a7ed0e35b60146d973a728ab9f390c8291f9547cee26c56427738` | CraxsRAT | KNOWN | 2/38 | Malware |  |  |
| `b9ddc7c5f9adbf012494ab258acd80ab35311b52e3b28f2a78a1d8dad75ab259` | Crocodilus | Android.Dropper.Generic | 7/23 |  |  |  |
| `d0279f6afa15e29234f752229e9b91312fc118f1c73971a2042e163d586c3792` | Ermac | Android.Trojan.AVerseFalc | 9/36 |  | SUSPICIOUS | ermac score=10 |
| `a778818cc08d213d1f66db5fa8b34aabc862569ecb99fd1aea37ff6ccab48400` | FluBot | Android.Trojan.BankBot | 10/37 |  | LIKELY_MALICIOUS | flubot score=10 |
| `45f232ed48389196190252e0abb31606422d0894ff48c593571662579b087686` | Gentlemen | KNOWN | 1/36 |  | NO_THREAT | gentlemen score=10 |
| `a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b` | GhostGrab | Android.Packed.Generic | 7/24 | Malware | MALICIOUS | ghostgrab score=10 |
| `173192ec576111adbc0c228f75244cf627513c95ca1709036e9850f0cdb7c90b` | GhostRAT | Android.Backdoor.GhostRAT | 10/36 | Malware | NO_THREAT | nfcshare score=10 |
| `a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782` | GodFather | Android.Infostealer.Banbra | 11/36 | Malware | MALICIOUS | godfather score=10 |
| `c2d2a636a84eba961d7c31da2fd7a2d87868935b57833093e376dc5816b4d2e1` | Harly | KNOWN | 2/24 |  | LIKELY_MALICIOUS | score=7 |
| `e084a327fde5523b1803040fc1ea40be84bc8434913d37d01083890c351dec96` | Herodotus | Android.Trojan.Generic | 5/24 | Malware | NO_THREAT | score=7 |
| `6ca691c97ab0028ce9acade5d079289668b1d0339ad330181c84fc7e7114c509` | Hook | Android.Trojan.Multiverze | 8/24 | Malware | MALICIOUS | hook score=10 |
| `d300e348a236c6fc23bceae84fdbd6deecf8f41565c032c0d062733fcb066a6e` | Hydra | Android.Trojan.Ravartar | 14/38 | Malware | MALICIOUS | hydra score=10 |
| `425469176c41994bc33ce0582948798875f5c9682b7d0967c925a10f813e1a3d` | IRATA | Android.Trojan.Generic | 9/24 | Malware | NO_THREAT | irata score=10 |
| `a15e50a753028ff9db51885705d6348113dac5b653cd2bd00dcfd8b97da7566a` | JackSkid | Linux.Worm.Mirai | 12/24 | NotCategorized | LIKELY_MALICIOUS | score=6 |
| `2fa0f3893ca8fff0ba2c2e30d0ba35712ec5dffa27ebe1b87b4a26cb4f7d0aa4` | Joker | KNOWN | 1/36 | Malware |  | score=6 |
| `ae5483625f278378e9d8930562c3be0dc41c9132fbcaad3894c78b76eb986141` | KATARU | Linux.Exploit.CVE-2026-43284 | 16/23 | Malware |  | mirai score=10 |
| `6875957f69028a7cde72961968df5ccdef896709d0114851313bb9a6a66d7349` | MetaSploit | Android.Hacktool.MetaSploit | 18/38 | Malware | MALICIOUS | score=None |
| `61f6ab5b07b1bef78e25da133d0a6df09a54f34d15c2b1dc2fdb6306ce567fce` | Metasploit | Android.Hacktool.MetaSploit | 18/38 | Malware | MALICIOUS | metasploit score=10 |
| `c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740` | Mirai | Linux.Worm.Mirai | 17/36 | Malware | LIKELY_MALICIOUS | score=6 |
| `3613a76be3c6f0d7f6108920cbd4bcedc4c9a4c3607136a747f77f3c099f7322` | Monokle | Android.Trojan.Multiverze | 5/38 |  | SUSPICIOUS | score=1 |
| `b17d030bee752859158181d586644569e40dfe13b0fd470f124829b5fbeddc26` | NGate | KNOWN | 1/24 | NotCategorized |  | ngate score=10 |
| `ca3da13d69ce07ed9b31314f2404f9c6a2235067406b545d7b00517258cee9d6` | Octo | Android.Trojan.Generic | 19/38 |  |  | octo score=10 |
| `1fa2150192384a7abb27ad92295aa937efca1b2ac88dc802d3a68082d61c38e9` | PhantomCard | Android.Trojan.Multiverze | 13/38 | Malware | LIKELY_MALICIOUS | phantomcard score=10 |
| `557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df` | PixRevolution | Android.Trojan.Multiverze | 14/38 | Malware | LIKELY_MALICIOUS | pixrevolution score=10 |
| `f6bf91fd210cf04592949131b3ed1a4a10986c9bdeebb4869f511b42c54c5328` | RatHat | Android.Hacktool.Multiverze | 10/23 | Malware | LIKELY_MALICIOUS | rathat score=10 |
| `e7ebac9ba2548db5e772f1a0d657acf0f61425e67cf326bea142a1f1c13a077d` | RedHook | Android.Spyware.Multiverze | 6/21 | Malware | MALICIOUS | redhook score=10 |
| `71c78101f7792fe879a082e323fed89c5e4a43132d01d3f79ed02afd8db45497` | SharkBot | Android.Spyware.Sharkbot | 16/25 |  | SUSPICIOUS | sharkbot score=10 |
| `58f639084f153ff5241b8ee7de3aba11dc5db2cebbb755f8c17c1091b030f594` | SilentNet | KNOWN | 2/38 | NoThreats | NO_THREAT | score=3 |
| `a71d97faedf467e161e83f05ec1a8285daa62cbcd192ea624d2a8a57a8e50e01` | Silentnet | KNOWN | 1/36 | NotCategorized |  | score=3 |
| `724a56172f40177da76242ee169ac336b63d5df85889368d1531f593b658606b` | Sova | Android.Trojan.Multiverze | 14/24 |  | MALICIOUS | sova score=10 |
| `3745e0fb7edbdd8da57f44f5ee1d2b2cc0db5d7f8b63ea69ce12ce561402cf17` | SpinOK | Android.Spyware.SpinOK | 8/37 |  | INFORMATIONAL | spinok score=10 |
| `97e63e6063345318325b666c54cdffb474725349d948626ef5671bb22020e335` | SpyMax | Android.Spyware.SpyNote | 11/38 |  | LIKELY_MALICIOUS | spymax score=10 |
| `3c0edd3c80f917d0045ac51d177e9a4768df5a66517005b0f7944423aa54b089` | SpyNote | Win32.Trojan.Qwexlafiba | 3/24 | Malware | MALICIOUS | score=6 |
| `554e71b4e5d2a172707b51edc8e0e22cba40858b69884e75228c12718c47e1ef` | TeaBot | Android.Infostealer.BankBot | 7/37 |  |  | score=5 |
| `47bb7f855cdf116c62499240089fa1b7a69585e8b7f639e192b9d038da4094cd` | Teabot | Android.Infostealer.Generic | 8/33 |  | LIKELY_MALICIOUS | teabot score=10 |
| `e40dc70d94e13e7fc1a58c9b940591bc01c1c37641f2ee61737c7625aa467c02` | TgToxic | Android.Packed.Generic | 6/38 |  |  | tgtoxic score=10 |
| `41752e7b3d8374ec74b94ebc258a0fefd3d41a44bb07a43d85546701afb50e36` | TheTruthSpy | Android.Spyware.Nidb | 12/24 |  |  | truthspy score=10 |
| `5c9f3c404d5ea7405a236c01b8b598b3f794b246ec0c7e52450844518ebaf9f0` | Triada | Win32.Trojan.Qwexlafiba | 6/24 | Malware | MALICIOUS | triada score=10 |
| `f4d7e9ec4eda034c29b8d73d479084658858f56e67909c2ffedf9223d7ca9bd2` | Vultur | Android.Spyware.Vultur | 14/24 |  | LIKELY_MALICIOUS | vultur score=10 |
| `49bc43a5b94d4a24f5561a98e3feac970fa37e9922a892f72351d5e94d77bc4c` | hydra | Android.Infostealer.Generic | 1/41 |  | MALICIOUS | score=7 |
| `4d814fdfb79b50f4da1cdcc3aca7fbcc4c9c1826cdbdcce86cfd72906dbe8f8f` | AhMyth | Android.Spyware.Ahmyth | 12/24 |  | LIKELY_MALICIOUS | ahmyth score=10 |
| `0c485d9cbf8aae82788b863512c750ea0b01a859ac4c7ae2461ed52482c02fed` | Ahmyth | Android.Trojan.Ahmyth | 11/24 | Malware |  | ahmyth score=10 |
| `3269a0116ce0915afdd32e8d87b05ae9f5c00fcf0a6729add39a6a87aaf30089` | Albiriox | Android.Trojan.Multiverze | 5/37 | Malware | MALICIOUS | score=7 |
| `208e85cc66f2ee482dce1c6ee5f1ea45592e9fc9980c1b04b5157975d127dcf1` | Alien | Android.Infostealer.Cerberus | 8/39 |  | MALICIOUS | score=3 |
| `d62705186c488bb26fccdb1404931223a887004fd6704ac1483e599a15e92792` | AndroRAT | Android.Trojan.AndroRAT | 24/43 |  |  | score=8 |
| `392272ef515d2f60f2c058675d637bf63a265800b8e4613ed9f72eeb8ebb323d` | Anubis | Android.Infostealer.Anubis | 10/38 | Malware | MALICIOUS | score=6 |
| `27e0ec79dbb7c7f99b43c8c01a94188d1071d1245b1745d0e066ae774c78a8f8` | BRATA | Android.Infostealer.BasBanke | 8/39 |  | LIKELY_MALICIOUS | brata score=10 |
| `cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15` | BankBot | Android.Trojan.Coper | 13/37 | Malware | MALICIOUS | score=6 |
| `1faeeec49012ef73fbe7fabcb325b0b849f64a967c9d0d777c80da9870a34b70` | BingoMod | KNOWN | 4/38 |  |  | bingomod score=10 |
| `5baaef4c3aad7d78959554a977f358fb37eae685034df70fa43c4b4618cba3a9` | BtmobRAT | Android.Trojan.BTMOBRat | 10/24 | Malware | NO_THREAT | btmobrat score=10 |
| `2152b98a832ce3e442b486ceeaa8e41a8a99657168986757913e2d916c7b1c21` | CECbot | Linux.Worm.Mirai | 18/38 | Malware | MALICIOUS | cecbot score=10 |
| `8beae1f6b21cec17eed82fb7af25e1782d5b7bf10fd22369603313f1b1a5e5e4` | Cerberus | Android.Infostealer.Anubis | 10/38 |  | LIKELY_MALICIOUS | cerberus score=10 |
| `153410238d01773e5c705c6d18955793bd61cb2e82c5c7656e74563bb43b3ffa` | Chameleon | Android.Trojan.Generic | 7/37 |  | MALICIOUS | score=7 |
| `dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8` | Coper | Android.Dropper.Generic | 14/38 | Malware | SUSPICIOUS | octo score=10 |
| `7cf365d61e59d5c3dd50295b1d5a0c360da9eba1b4dc00cdc0f1ceee4a5cc412` | Copybara | KNOWN | 3/36 | Malware | MALICIOUS | copybara score=10 |
| `801f956057aa608c7393b2fcca9b731c610c6bd5e14f4f3c1d64e8f211828319` | Crocodilus | Android.Infostealer.Anubis | 7/23 |  |  |  |
| `14b005352c07490b3689ac4eb187eb68d2b50cd135e57e1bca2f3469b10e2dd5` | Ermac | Android.Trojan.Ermac | 10/23 |  | SUSPICIOUS |  |
| `a959108ec8f93ee4c71e588236788d17372f9d61b8f71a509a776f097889f36b` | FluBot | Android.Dropper.Generic | 9/23 |  |  | flubot score=10 |
| `c2bccfc8b3bdf2da5fb5c22055a9c4859256be7904933e9e0b92fa31fd0420d3` | GodFather | Android.Infostealer.Generic | 9/37 |  | LIKELY_MALICIOUS | godfather score=10 |
| `29926c0101734a0c34efd310d58d055f266e28960c65f00f905327dcbb186711` | Harly | KNOWN | 2/38 |  | MALICIOUS | score=7 |
| `2b332adf4e52168cbd2e76866165a5c6f421d15b5778d44f78f0d86c4c26b9fa` | Hook | Android.Trojan.Egairtigado | 5/24 |  | LIKELY_MALICIOUS | bingomod score=10 |
| `810926f89430144fd258ed4a95f1d77215f657a4e7dac2ce0c410bcffbdca99e` | Hydra | Android.Trojan.Badpack | 9/36 | Malware |  | hydra score=10 |
| `5d5c21fbab62ec156c8e3897caf31a0dfb1a2bf2e1198a9e9b8ecdea87089a19` | IRATA | KNOWN | 10/38 | Malware | NO_THREAT | irata score=10 |
| `1a9a54eb8b3ed707852eace623b935bc687c46d5e0cfa793751e778dacd8b62b` | JackSkid | Linux.Worm.Mirai | 12/24 | NotCategorized | LIKELY_MALICIOUS | score=6 |
| `94e0dd4f976cb66058f7aae7b69d308444bec8450065be0e4b7e0351cee5692c` | Joker | KNOWN | 1/38 | Malware | NO_THREAT | score=6 |
| `0a592e8cbc7f6ece7de140a8f49c359fbf152f3d7bab474eb0f52f521f3e56c3` | KATARU | Linux.Worm.Mirai | 14/38 | Malware |  | score=6 |
| `77ffe8b7b3efa39fa35daaee1f70f560079c96c680f9d9d85997d658e2b367a9` | Metasploit | Android.Hacktool.MetaSploit | 14/24 | Malware | MALICIOUS | metasploit score=10 |
| `089688db8500d0776501de520205209535bf0e5104d0a728f484dde75c1ed9c2` | Mirai | Linux.Worm.Mirai | 15/38 | NoThreats | LIKELY_MALICIOUS | score=6 |
| `af56cbeba5bb0e5b10af555f7380214d89f8f1bfcca229f2e713c7eb4a371630` | NGate | KNOWN | 0/38 | NotCategorized | NO_THREAT | ngate score=10 |
| `0a2f1bdec6df99d0de397ffdd63f1c89341b7bd53fa4dd5868e567109fdd507f` | Octo | Android.Infostealer.SmsForward | 6/23 |  |  | score=1 |
| `8e39fb18e8acb2e4fc4bcd7db2efc320f5ec84100e8ba870fd24dd13a6584277` | PixRevolution | Android.Trojan.Multiverze | 9/24 | Malware | MALICIOUS | pixrevolution score=10 |
| `fa7947933a3561b7174f1d94472dcf8633a03749c14342ce65dafe94db361140` | SharkBot | Android.Malware.Sharkbot | 6/41 |  | SUSPICIOUS | score=7 |
| `1ae3e8213b07e1d53eca54a1901e2dc6dc9e27a3ca10377a63e6adec2fe15426` | SilentNet | KNOWN | 4/23 | NoThreats | NO_THREAT | score=3 |
| `376d13affcbfc5d5358d39aba16b814f711f2e81632059a4bce5af060e038ea4` | Sova | Android.Trojan.Generic | 10/24 |  | INFORMATIONAL | sova_v5 score=10 |
| `cde47bed5ec83e29f6455ec35228c3f56d488393668f5b720b79fcd6cb3bc098` | SpyMax | Android.Trojan.Phonzy | 12/38 |  | MALICIOUS | spymax score=10 |
| `d472e114361dd2c6ebafb60daa72ba2db09752de5b243538f0fee18410ad6a25` | SpyNote | Android.Trojan.AVerseFalc | 7/24 | Malware | MALICIOUS | ghostbat score=10 |
| `ddabe5999dbc9ffbc8b804a7ea6bb61415bc88e346b2d2c0d53bfff9dcc88d32` | TeaBot | Android.Trojan.Multiverze | 13/26 |  | LIKELY_MALICIOUS | teabot score=10 |
| `9f2d916b1e0ee486f5a49e3e9887eae59dbdca0a554139ae9a4dc8edc2f12de0` | Teabot | Android.Dropper.BankBot | 6/46 |  |  | teabot score=10 |
| `fde931224d2e558e67ac8c9c0c1d0aac4f7562622a67870d6c3024bdeb851676` | TgToxic | Android.Trojan.ScarletFlash | 8/24 |  | SUSPICIOUS | tgtoxic score=10 |
| `de7d54276047fc457271b582a378e9599ce0b3822d4e9cb89a1260f81a3c2644` | Triada | Android.Trojan.Alevaul | 5/22 | Malware | MALICIOUS | triada score=10 |
| `3853c41d87d5aa64abe9a52cd1b1fb5e6abada57a06289c9ba9172b5036740b2` | Vultur | Android.Trojan.Multiverze | 6/24 |  |  | score=8 |

## Где внутри APK лежит детектируемый код

| Файл | Кол-во APK |
|---|---|
| `classes.dex` | 74 |
| `AndroidManifest.xml` | 17 |
| `classes2.dex` | 14 |
| `classes3.dex` | 7 |
| `libbot.so` | 5 |
| `resources.arsc` | 4 |
| `libattack.so` | 4 |
| `libTCqnfQ.so` | 4 |
| `libMJnWUXJ.so` | 4 |
| `?` | 4 |
| `lol` | 3 |
| `classes5.dex` | 3 |
| `classes4.dex` | 3 |
| `1.bt` | 2 |
| `libsafedk.so` | 2 |
| `Mellat.zip` | 1 |
| `Банковский троян.apk` | 1 |
| `index.html` | 1 |
| `xmrutil.so` | 1 |
| `config.json` | 1 |

## Образцы (первые 100 с отчётом VT)

| SHA-256 | Семейство | VT | Kaspersky | ESET-NOD32 | Avast-Mobile | DrWeb | Вредоносные файлы внутри |
|---|---|---|---|---|---|---|---|
| `a15e50a753028ff9db51885705d6348113dac5b653cd2bd00dcfd8b97da7566a` | JackSkid | 42/68 | HEUR:Backdoor.Linux.Mirai.ld | Android/Agent.FSQ trojan | Android:Evo-gen [Trj] | Android.Siggen.Susp2.4485 | `lol` (35)<br>`classes.dex` (6) |
| `ae5483625f278378e9d8930562c3be0dc41c9132fbcaad3894c78b76eb986141` | KATARU | 42/66 | HEUR:Exploit.Linux.CVE-2026-31431.c | Android/Agent.FVD trojan | Android:Evo-gen [Trj] | Android.Backdoor.Kyorij.2.origin | `libbot.so` (20)<br>`libbot.so` (20)<br>`libbot.so` (19) |
| `ca3da13d69ce07ed9b31314f2404f9c6a2235067406b545d7b00517258cee9d6` | Octo | 42/70 | UDS:Trojan-Dropper.Linux.Agent.gen | a variant of Android/TrojanDropper.Agent.LWH | Android:Evo-gen [Trj] | Android.BankBot.Coper.4363 | `libTCqnfQ.so` (32)<br>`classes.dex` (12)<br>`libTCqnfQ.so` (7) |
| `724a56172f40177da76242ee169ac336b63d5df85889368d1531f593b658606b` | Sova | 40/63 | HEUR:Trojan-Banker.AndroidOS.Sova.i | multiple detections | Android:Evo-gen [Trj] | Android.BankBot.992.origin | `9ae5523ea2a7080ac97ef5443bf4b781f775c67fefaec687e58b5b983caf3146` (25)<br>`classes.dex` (23) |
| `1a9a54eb8b3ed707852eace623b935bc687c46d5e0cfa793751e778dacd8b62b` | JackSkid | 40/67 | HEUR:Backdoor.Linux.Mirai.ld | Android/Agent.FSQ trojan | ELF:Mirai-GH [Trj] | Android.Siggen.Susp2.4391 | `lol` (35)<br>`lol2` (33)<br>`classes.dex` (4) |
| `95a1793b5bd345b18eda377e529d74f360590764bf454dee96575e2f31706723` | trojan.basdoor/spyagent | 40/64 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.Spy.4521 | `classes.dex` (24) |
| `a778818cc08d213d1f66db5fa8b34aabc862569ecb99fd1aea37ff6ccab48400` | FluBot | 39/67 | HEUR:Trojan-Banker.AndroidOS.Bian.f | Android/TrojanDropper.Agent.ICZ trojan | Android:Evo-gen [Trj] | Android.BankBot.9305 | `classes.dex` (20) |
| `47bb7f855cdf116c62499240089fa1b7a69585e8b7f639e192b9d038da4094cd` | Teabot | 39/66 | HEUR:Trojan-Banker.AndroidOS.Agent.io | Android/TrojanDropper.Agent.IVA trojan | APK:RepMalware [Trj] | Android.BankBot.11270 | `classes.dex` (20)<br>`AndroidManifest.xml` (6)<br>`CERT.RSA` (4) |
| `153410238d01773e5c705c6d18955793bd61cb2e82c5c7656e74563bb43b3ffa` | Chameleon | 39/68 | HEUR:Trojan-Dropper.AndroidOS.Hqwar.ia | Android/TrojanDropper.Agent.LCK trojan | Android:Evo-gen [Trj] | Android.BankBot.14812 | `classes.dex` (23) |
| `376d13affcbfc5d5358d39aba16b814f711f2e81632059a4bce5af060e038ea4` | Sova | 39/66 | HEUR:Trojan-Dropper.AndroidOS.Hqwar.hr | Android/TrojanDropper.Agent.LAU trojan | Android:Evo-gen [Trj] | Android.BankBot.14551 | `classes.dex` (23)<br>`classes2.dex` (1) |
| `cde47bed5ec83e29f6455ec35228c3f56d488393668f5b720b79fcd6cb3bc098` | SpyMax | 39/67 | HEUR:Trojan-Spy.AndroidOS.SpyNote.bo | Android/Spy.SpyMax.B trojan | Android:Evo-gen [Trj] | Android.Hidden.1.origin | `classes.dex` (29) |
| `ddabe5999dbc9ffbc8b804a7ea6bb61415bc88e346b2d2c0d53bfff9dcc88d32` | TeaBot | 39/68 | HEUR:Trojan-Dropper.AndroidOS.Hqwar.bk | Android/TrojanDropper.Agent.IVA trojan | Android:Evo-gen [Trj] | Android.BankBot.11270 | `classes.dex` (19) |
| `1c273110f3aec84e76b13dff60521cc65731ef83657240f09cc9f5e0b1926c32` |  | 39/62 | HEUR:Trojan.AndroidOS.Piom.aiuj | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `18bfe9187812ebf2c07f42bc73f4c0f79b9d2ca89fa0d97f35d026507eb67815` (18) |
| `04b4f6aefde0a647337e2000dfc18ae5c1b973bbe57571322eed408fb0ecee0a` |  | 39/64 | HEUR:Trojan-Spy.AndroidOS.SmsThief.tt | a variant of Android/TrojanSMS.Agent.CWR | Android:Evo-gen [Trj] | Android.SmsSpy.7189 | `b41ea59bc9a940702832cbbb93c5500b111171ac581a0a629411a285d4eac0e6` (23) |
| `360fbf0eef153c745ca790d7e2222f1c0ea6e3edcbd42fb16d30b2f24e4dc402` | trojan.smsspy/fiej | 39/67 | HEUR:Trojan-Spy.AndroidOS.Agent.zv | a variant of Android/Spy.SmsSpy.SO | Android:Evo-gen [Trj] | Android.SmsSpy.830.origin | `classes.dex` (26) |
| `f4d7e9ec4eda034c29b8d73d479084658858f56e67909c2ffedf9223d7ca9bd2` | Vultur | 38/68 | HEUR:Trojan-Spy.AndroidOS.Agent.aco | Android/Spy.Vultur.A trojan | Android:Evo-gen [Trj] | Android.BankBot.847.origin |  |
| `d62705186c488bb26fccdb1404931223a887004fd6704ac1483e599a15e92792` | AndroRAT | 38/67 | HEUR:Trojan-Spy.AndroidOS.Agent.acj | Android/Spy.CapraRAT.A trojan | Android:Androrat-CG [Rat] | Android.Backdoor.690.origin | `classes.dex` (32) |
| `4ed2c0888048def2441087d03d847584c0f130c10e98d3978b80e4af8ef19fb7` | trojan.smsspy/cacosms | 38/67 | HEUR:Trojan-Spy.AndroidOS.Agent.aho | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `classes.dex` (12) |
| `df3d18f6b2ee85551b42324e59de7488afa9d459819a2e9cefe3e5ce5322939f` | trojan.smsspy/cacosms | 38/67 | HEUR:Trojan-Spy.AndroidOS.Agent.aho | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `classes.dex` (19) |
| `59cedb5ea89e38810819f149a4b9635866350d59e010c3133f8dda041577c9d7` | trojan.smsspy/fiej | 38/67 | HEUR:Trojan-Spy.AndroidOS.Agent.zv | a variant of Android/Spy.SmsSpy.SO | Android:Evo-gen [Trj] | Android.SmsSpy.830.origin | `classes.dex` (13) |
| `cb47e96d5c90d32dc9a55149e53fcc88b723a193bb5bf6b57db1d7cdef1d163c` |  | 38/64 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.SmsSpy.11058 |  |
| `4f59c653be63b76afef598868785659dff0e3fa320884008fb6bb2e5639aa5bd` | trojan.smsspy/fiej | 38/66 | HEUR:Trojan.AndroidOS.Boogr.gsh | a variant of Android/Spy.SmsSpy.SO | Android:Evo-gen [Trj] | Android.SmsSpy.830.origin | `classes.dex` (21) |
| `73ec42013f549f3b709852770c9e2769a56943173d304f939f6bcdf567cda4f1` |  | 38/65 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.CCJ | Android:Evo-gen [Trj] | Android.Spy.989.origin | `0fb18985cc8a8f2ad3fda402a061e97a9b1fc0387f5583f53eb7936fdef09cc5` (21) |
| `39ccc5d7009aefac18891c70a16b857b98481d6f69800075e31900c4dc9ef000` | Alien | 37/66 | HEUR:Trojan-Dropper.AndroidOS.Hqwar.hr | Android/TrojanDropper.Agent.LAK trojan | Android:Evo-gen [Trj] | Android.BankBot.14902 | `classes.dex` (17) |
| `1430dc0cc26adfb7b7715624602767af26f453e3f34df66f1a6d41c38a35819c` | BRATA | 37/67 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.Spy.989.origin | `classes.dex` (23)<br>`Mellat.zip` (1) |
| `1f333d910158316c6211f7b24d118aadca778abb3964f3a4b7d3914e49278b7d` | BtmobRAT | 37/66 | HEUR:Trojan-Spy.AndroidOS.SpyNote.dn | Android/Spy.Agent.EIK trojan |  | Android.SpyMax.72.origin | `xmrutil.so` (38)<br>`classes.dex` (15)<br>`classes2.dex` (14) |
| `71c78101f7792fe879a082e323fed89c5e4a43132d01d3f79ed02afd8db45497` | SharkBot | 37/67 | HEUR:Trojan-Downloader.AndroidOS.Banker.j | Android/TrojanDownloader.Agent.AAE trojan | APK:RepMalware [Trj] | Android.DownLoader.1069.origin | `classes.dex` (29) |
| `e3fc59d0c60dfdcc64778b39d70635db1824254206dcc78a38c77b66a6c99b33` | trojan.basdoor/spyagent | 37/66 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.Spy.4521 | `classes.dex` (24) |
| `5b0b1c7fc6e0677866a01483654d286ead9622dd3faf362133e28051bcf7989e` | trojan.basdoor/spyagent | 37/67 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.Spy.4521 | `classes.dex` (24) |
| `fdd19235e6886e2b4386a91852bb8bd464bbb08097d4bf4927c0a65a84276014` |  | 37/64 | HEUR:Trojan.AndroidOS.Boogr.gsh | a variant of Android/Spy.SmsSpy.SO | Android:Evo-gen [Trj] | Android.SmsSpy.830.origin | `?` (14) |
| `ca0d2a1f8081e66130801082ced73f04b8ac4f33adf6de58d4ca2a84bb6d799b` |  | 37/65 | HEUR:Trojan-Spy.AndroidOS.Agent.zp | a variant of Android/Spy.Agent.BVM | Android:Evo-gen [Trj] | Android.Spy.917.origin | `?` (17) |
| `1bd1533dc9b6dde06ada49109d583dac49098ee232e181f727c26fcce658b89b` |  | 37/65 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.CCJ | Android:Evo-gen [Trj] | Android.Spy.989.origin | `f4f1bb5772b9dc8ceefb171a761127269dd79cbb5907ab78a363dd39e671073d` (19) |
| `2152b98a832ce3e442b486ceeaa8e41a8a99657168986757913e2d916c7b1c21` | CECbot | 36/68 | HEUR:Backdoor.AndroidOS.Agent.il | Android/Mirai.J trojan | Android:Evo-gen [Trj] | Android.Mirai.7.origin | `libattack.so` (28)<br>`libattack.so` (27)<br>`classes.dex` (3) |
| `29926c0101734a0c34efd310d58d055f266e28960c65f00f905327dcbb186711` | Harly | 36/70 | HEUR:Trojan.AndroidOS.Harly.at | Android/Harly.BN | APK:RepMalware [Trj] |  | `libsafedk.so` (28)<br>`libsafedk.so` (14)<br>`classes5.dex` (2) |
| `77ffe8b7b3efa39fa35daaee1f70f560079c96c680f9d9d85997d658e2b367a9` | Metasploit | 36/66 | HEUR:Trojan-Downloader.AndroidOS.Masplot.p | Android/TrojanDownloader.Agent.JN trojan | Android:Evo-gen [Trj] | Android.RemoteCode.6833 | `classes.dex` (30)<br>`AndroidManifest.xml` (9) |
| `4e9e6b28830190b0ee3655b2a1c348ba037ef584c66c14dcca929cfc53233e6b` | trojan.smsspy/cacosms | 36/67 | HEUR:Trojan-Spy.AndroidOS.Agent.aho | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `classes.dex` (22)<br>`AndroidManifest.xml` (2) |
| `3d0985b998595dbcf3f136765f362da9c6033e42bc3388d2a5d708ac3b2dcf70` | trojan.basdoor/spyagent | 36/67 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.Spy.4521 | `classes.dex` (24) |
| `4c96a751c1ba60c3d28a9413d71166401c796d1acb3d5f93d4fee20db7984344` |  | 36/65 | HEUR:Trojan.AndroidOS.Piom.aiuj | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `21c5ac036951fc2f0d9a19eff6ef290e690ba2f9b814caeab0b5a5591e985a93.sample` (19) |
| `cb0dd3d4234c701c0dc146f557ad3f77af82cfa9f5d7f4518bd358951b3b8d8e` | trojan.smsspy/andr | 36/67 | HEUR:Trojan.AndroidOS.Boogr.gsh | a variant of Android/Spy.SmsSpy.SO | Android:Evo-gen [Trj] | Android.SmsSpy.830.origin | `classes.dex` (24)<br>`AndroidManifest.xml` (2) |
| `824bc8f232feb2eefdcdda66dd56baf2eb654ede2aa3f4ce2351da26900a05ca` | trojan.realrat/gaaq | 36/67 | HEUR:Trojan-Spy.AndroidOS.Realrat.l | a variant of Android/Spy.Agent.BUK | Android:Evo-gen [Trj] | Android.Spy.989.origin | `classes.dex` (10) |
| `28534866fd54d7c6c1b2d36b9987130a2125ad94145689449ddfc24c2a74593e` |  | 36/65 | HEUR:Trojan-Spy.AndroidOS.Realrat.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.Spy.989.origin | `e0ed82f6a411bdc005ff1947447308d629ca67b68d6a9225cd7b40aa9bbfe3fe` (16) |
| `7495392226c28c5aadab487648dfc9da5ce9f563c1deba3c52bce158dc72940e` |  | 36/64 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.SmsSpy.11058 | `f522ff3c447c5435113fa19c55b874e3d6820980daebcddecf4e892e759a4ec0` (23)<br>`ad7948b7088e711080e56de58a3ab2b7.virus` (2) |
| `bfc577ea1b9b326609d857e0c7ea4c7db5c382f86b3faeb92e9230da650b3af9` | AhMyth | 35/66 | HEUR:Backdoor.AndroidOS.Ahmyth.t | Android/Spy.Agent.BBW trojan | Android:Evo-gen [Trj] | Android.Spy.5171 | `classes.dex` (28)<br>`AndroidManifest.xml` (3)<br>`resources.arsc` (1) |
| `a9859c49d20baf131d1e9253acb0118fac412acaa97938d87c7c8daa7554cd54` | CECbot | 35/68 | HEUR:Backdoor.AndroidOS.Agent.il | Android/Mirai.J trojan | Android:Evo-gen [Trj] | Android.Mirai.7.origin | `libattack.so` (8)<br>`libattack.so` (8)<br>`classes.dex` (3) |
| `0628ad6d1fd836b13b22e75fa169502d8ce78b7ad20f0261eb5151da98437bca` | CoinMiner | 35/65 | HEUR:Trojan-Spy.AndroidOS.Btmob.e | Android/Spy.Agent.EUG trojan |  | Android.SpyMax.75.origin | `classes3.dex` (15)<br>`classes2.dex` (10) |
| `554e71b4e5d2a172707b51edc8e0e22cba40858b69884e75228c12718c47e1ef` | TeaBot | 35/65 | HEUR:Trojan-Banker.AndroidOS.Agent.io | Android/Spy.Banker.BUL trojan | Android:Evo-gen [Trj] | Android.BankBot.14643 | `2671e5339077e40bfdef3f3fa9a214f3b5327def4ecdde034b2ec2536585f015` (22) |
| `a7151099e1c44a2a7e6695e3c0d135012cbae04390bb52d1a56f8c2818a6f6a0` | trojan.spyagent/fkte | 35/67 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.SmsSpy.11058 | `classes.dex` (23)<br>`AndroidManifest.xml` (2) |
| `2652bd208ccd07637d7be824570290e700d8d6eb39193c431948bcf17af4a19c` |  | 35/59 | HEUR:Trojan-Spy.AndroidOS.Agent.zv | a variant of Android/Spy.SmsSpy.SO | Android:Evo-gen [Trj] | Android.SmsSpy.830.origin | `dff5691e133ff0226e879999cb76a04a2f46918df49670d78c3bb84bc66d4b32` (32)<br>`3c1b83c182a849c2bcc4a85f32599787.virus` (1) |
| `bd95e05f1864f36e1e59c0ad6b1956cfd5a00a3fa884b2833d777f12639ee9a9` | trojan.smsspy/fkng | 35/67 | HEUR:Trojan-Spy.AndroidOS.Agent.aho | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `classes.dex` (7)<br>`AndroidManifest.xml` (2) |
| `9b020d58e01e1c6f317111d41fe635607c5d6c37542d70f391a64e5d8aa7af43` |  | 35/65 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.Spy.4521 | `feadf134ab94f382209a6fca04d40ef734a5c2f8d55ac271e04c987b81adca41` (23) |
| `cdd0d2e6639bfb11299b168748c77bced8821075c6cb04ed4b1f888a369228fd` | Ahmyth | 34/66 | HEUR:Backdoor.AndroidOS.Ahmyth.t | Android/Spy.Agent.BBW trojan | Android:Evo-gen [Trj] | Android.Spy.5171 | `classes.dex` (29) |
| `6875957f69028a7cde72961968df5ccdef896709d0114851313bb9a6a66d7349` | MetaSploit | 34/66 | HEUR:Trojan-Downloader.AndroidOS.Masplot.p | Android/TrojanDownloader.Agent.JN trojan | Android:Evo-gen [Trj] | Android.RemoteCode.6833 | `classes.dex` (24)<br>`AndroidManifest.xml` (9) |
| `c48071a9e15df2cad4c027a92370aab2f0187eec5438977c47463d505f271740` | Mirai | 34/68 | HEUR:Backdoor.AndroidOS.Mirai.w | Android/Agent.FVD trojan | ELF:Mirai-BOH [Trj] | modification of Android.Backdoor.Kyorij.2.origin | `ntxevzsb.exe` (12)<br>`libbot.so` (11)<br>`libbot.so` (11) |
| `27e0ec79dbb7c7f99b43c8c01a94188d1071d1245b1745d0e066ae774c78a8f8` | BRATA | 34/64 | HEUR:Trojan-Banker.AndroidOS.Basbanke.n | a variant of Android/TrojanDropper.Agent.FQN | Android:Evo-gen [Trj] | Android.Packed.54935 | `097a6cdbff2f5807de294f546f00fcb0.virus` (2) |
| `dc2a780f6abb9f0ec0a6675f20acb91ebe2a8748297682a59daf9164fbea2ee8` | Coper | 34/63 | HEUR:Trojan-Banker.AndroidOS.Coper.c | Android/TrojanDropper.Agent.LWH trojan | Android:Evo-gen [Trj] | Android.BankBot.Coper.9160 | `libMJnWUXJ.so` (20)<br>`libMJnWUXJ.so` (9)<br>`libMJnWUXJ.so` (4) |
| `9f2d916b1e0ee486f5a49e3e9887eae59dbdca0a554139ae9a4dc8edc2f12de0` | Teabot | 34/68 | HEUR:Trojan-Banker.AndroidOS.Bian.g | a variant of Android/TrojanDropper.Agent.ICZ | Android:Evo-gen [Trj] | Android.BankBot.9305 | `classes.dex` (20)<br>`resources.arsc` (1) |
| `769587309d3182f0594a5ade73b7ce0e3593800786cd07edb631e4be01578d3b` |  | 34/64 | HEUR:Trojan.AndroidOS.Piom.aiuj | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `?` (8) |
| `64394537e0043a0d7f29ac7a914e9daf936f49cd57953898e996aa42229a6173` |  | 34/63 | HEUR:Trojan-Spy.AndroidOS.Realrat.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.Spy.989.origin | `unknown` (15) |
| `5223d17721ad60b71e9a811da2f7c3a290f99a214884a2b743cbb4c5151a7f2f` | trojan.basdoor/andr | 34/66 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.CCI | Android:Evo-gen [Trj] | Android.Spy.989.origin | `ec9c1eb78187d23d5c8b6282288f0d1f6530479944414c0faaf56f4e57656c0a` (20)<br>`AndroidManifest.xml` (3) |
| `97e63e6063345318325b666c54cdffb474725349d948626ef5671bb22020e335` | SpyMax | 33/67 | HEUR:Trojan-Spy.AndroidOS.SpyNote.e | a variant of Android/Spy.SpyMax.E | Android:Evo-gen [Trj] | Android.SpyMax.4.origin | `23964468552b2351b7d1fa08ef9fef495ebe8664bebb12de63126b85c5cbf2de` (24) |
| `0c485d9cbf8aae82788b863512c750ea0b01a859ac4c7ae2461ed52482c02fed` | Ahmyth | 33/67 | HEUR:Backdoor.AndroidOS.Ahmyth.t | Android/Spy.Agent.BBW trojan | Android:Evo-gen [Trj] | Android.Spy.5171 | `classes.dex` (31)<br>`AndroidManifest.xml` (3)<br>`resources.arsc` (1) |
| `208e85cc66f2ee482dce1c6ee5f1ea45592e9fc9980c1b04b5157975d127dcf1` | Alien | 33/61 | HEUR:Trojan-Banker.AndroidOS.Coper.a | a variant of Android/Spy.Banker.AOJ | Android:Cerberus-EA [Bank] | Android.BankBot.745.origin |  |
| `8beae1f6b21cec17eed82fb7af25e1782d5b7bf10fd22369603313f1b1a5e5e4` | Cerberus | 33/66 | HEUR:Trojan-Dropper.AndroidOS.Hqwar.ia | Android/TrojanDropper.Agent.LSH trojan | APK:RepMalware [Trj] | Android.BankBot.14908 | `classes.dex` (22) |
| `2157a24f1a6a326007eafece5d54d7e1bcebd6781c49ccfc92e4f26f9922d4f8` |  | 33/57 |  | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `c472eca98d5855184dd955a813e1932c77c48359d7adb8baf5670306f6887434` (18) |
| `cd80803a83b37e448de37e30b158106ca53a2e98e1c6a73ad0d6b89547d4d17d` |  | 33/62 | HEUR:Trojan.AndroidOS.Piom.aiuj | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `AndroidManifest.xml` (2) |
| `c5ab0adaedf391a395387df33b0bf6854f1ccc9c5da937915ea86b5eec6e6103` | AndroRAT | 32/65 | HEUR:Trojan-Spy.AndroidOS.Agent.abg | Android/Spy.Agent.BEL trojan | Android:Evo-gen [Trj] | Android.Spy.1131.origin | `classes.dex` (24)<br>`AndroidManifest.xml` (6) |
| `a25bf4bdb2ed9872456af0057eb21ce31fd03d680d63a9da469519060b4814bc` | BlackRock | 32/67 | HEUR:Trojan-Dropper.AndroidOS.Hqwar.fc | Android/TrojanDropper.Agent.HNB trojan | Android:Evo-gen [Trj] | Android.BankBot.3927 | `classes.dex` (26)<br>`index.html` (2) |
| `41752e7b3d8374ec74b94ebc258a0fefd3d41a44bb07a43d85546701afb50e36` | TheTruthSpy | 32/66 | not-a-virus:HEUR:Monitor.AndroidOS.Nidb.b | Android/Monitor.Spyoo.P application | Android:Evo-gen [Trj] | Program.Spyoo.3.origin | `classes.dex` (29) |
| `d19bb4b16b00b6c088c624dd7a7f130e688c6502143c1763a572cf0b77ac7dfc` | trojan.basdoor/gaap | 32/67 | HEUR:Backdoor.AndroidOS.Basdoor.c | a variant of Android/Spy.Agent.CCM | Android:Evo-gen [Trj] | Android.Spy.989.origin |  |
| `f13ac0b04207652d9ef1094ce3504e791df223bbacf6e07dfb162d4e099d7105` |  | 32/61 | HEUR:Trojan.AndroidOS.Piom.aiuj | a variant of Android/Spy.SmsSpy.TN | Android:Evo-gen [Trj] | Android.SmsSpy.10966 | `?` (8)<br>`AndroidManifest.xml` (2) |
| `eb2e0ce12822b17392bb163ed594768c15a4e06eee50447bfc4e8e6cf3a350fd` |  | 32/61 | HEUR:Trojan-Spy.AndroidOS.Realrat.c | a variant of Android/Spy.Agent.BWC | Android:Evo-gen [Trj] | Android.SmsSpy.11058 |  |
| `a6ea793e52823218041ededc61900c6ea273b50ec64d32c4d2a3ce722450705b` | GhostGrab | 31/65 | HEUR:Trojan-Dropper.AndroidOS.Banker.ab | Android/TrojanDropper.Agent.MSN trojan | APK:RepMalware [Trj] | Android.Packed.73.origin | `classes.dex` (10) |
| `61f6ab5b07b1bef78e25da133d0a6df09a54f34d15c2b1dc2fdb6306ce567fce` | Metasploit | 31/65 |  | Android/TrojanDownloader.Agent.JN trojan | Android:Evo-gen [Trj] | Android.RemoteCode.6833 | `classes.dex` (25)<br>`AndroidManifest.xml` (9) |
| `4d814fdfb79b50f4da1cdcc3aca7fbcc4c9c1826cdbdcce86cfd72906dbe8f8f` | AhMyth | 31/63 | HEUR:Backdoor.AndroidOS.Ahmyth.t | Android/Spy.Agent.BEH trojan | Android:Evo-gen [Trj] | Android.Spy.5700 | `classes.dex` (29)<br>`AndroidManifest.xml` (3) |
| `cadcce6d4088c72fd0779d59d00f5753eaab585a263e3c92374df29ae767ac15` | BankBot | 31/68 | HEUR:Trojan-Banker.AndroidOS.Coper.c | Android/TrojanDropper.Agent.NBV trojan | Android:Evo-gen [Trj] | Android.MulDrop.245.origin | `9W` (29)<br>`classes.dex` (12) |
| `0a2f1bdec6df99d0de397ffdd63f1c89341b7bd53fa4dd5868e567109fdd507f` | Octo | 31/68 | HEUR:Trojan-Banker.AndroidOS.Coper.a | a variant of Android/Spy.Banker.AZL | Android:Evo-gen [Trj] | Android.BankBot.Coper.12.origin | `c9239690da0726c6de20ce482b0e84945c75bd1f167948c3910bf311fe7327f8` (23) |
| `d300e348a236c6fc23bceae84fdbd6deecf8f41565c032c0d062733fcb066a6e` | Hydra | 30/65 | HEUR:Trojan-Banker.AndroidOS.Bian.h | Android/TrojanDropper.Agent.IVA trojan | Android:Evo-gen [Trj] | Android.BankBot.11270 | `classes.dex` (6) |
| `557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df` | PixRevolution | 30/64 | UDS:Trojan-Banker.AndroidOS.Agent.abd | Android/Agent.FOQ trojan | APK:RepMalware [Trj] | Android.Banker.1067.origin | `classes2.dex` (18) |
| `14b005352c07490b3689ac4eb187eb68d2b50cd135e57e1bca2f3469b10e2dd5` | Ermac | 30/66 | HEUR:Trojan-Banker.AndroidOS.Ermak.a | a variant of Android/Spy.Banker.CHE | Android:Ermac-C [Bank] | Android.BankBot.Ermac.13.origin |  |
| `fa7947933a3561b7174f1d94472dcf8633a03749c14342ce65dafe94db361140` | SharkBot | 30/66 | HEUR:Trojan-Downloader.AndroidOS.Banker.r | Android/TrojanDownloader.Agent.AAK trojan | APK:RepMalware [Trj] | Android.DownLoader.1105.origin | `classes.dex` (14) |
| `8166dfba7fd0b4ad44c8bc91cc0e98fa06b8912e3fca2093900eb58ba79d22d4` | BankBot | 29/67 | HEUR:Trojan-Banker.AndroidOS.Coper.c | Android/TrojanDropper.Agent.NBV trojan | Android:Evo-gen [Trj] | Android.MulDrop.245.origin | `Банковский троян.apk` (25)<br>`classes.dex` (6) |
| `3613a76be3c6f0d7f6108920cbd4bcedc4c9a4c3607136a747f77f3c099f7322` | Monokle | 29/63 | HEUR:Trojan-Spy.AndroidOS.Monocle.k | Android/Spy.Agent.DLD trojan |  | Android.Monokle.5.origin |  |
| `f6bf91fd210cf04592949131b3ed1a4a10986c9bdeebb4869f511b42c54c5328` | RatHat | 29/67 | HEUR:Trojan.AndroidOS.Dvmap.a | Android/Spy.Agent.GAX trojan | APK:RepMalware [Trj] | Android.Spy.1768.origin |  |
| `5baaef4c3aad7d78959554a977f358fb37eae685034df70fa43c4b4618cba3a9` | BtmobRAT | 29/66 | HEUR:Trojan-Spy.AndroidOS.SpyNote.dn | Android/Spy.Agent.EVJ trojan | Android:Evo-gen [Trj] | Android.SpyMax.581 | `classes.dex` (6)<br>`classes2.dex` (4)<br>`classes3.dex` (4) |
| `49c96c56a5b73d068e63edeacffaa1344a97c521d2eb15856db32fda1edc2bcd` |  | 29/62 | HEUR:Trojan-Spy.AndroidOS.Realrat.h | a variant of Android/Spy.Agent.BUK | Android:Evo-gen [Trj] | Android.Spy.989.origin |  |
| `e84005a2c1686ec21fc90de1ee81998670e4b67ff7f4b429421fe59249cfe5b6` |  | 29/61 | HEUR:Trojan-Spy.AndroidOS.Realrat.h | a variant of Android/Spy.Agent.BUK | Android:Evo-gen [Trj] | Android.Spy.989.origin |  |
| `a52d2105d680d029f9cc5c9c77f639e47ae520e41ce7294bbad77b8f2931796a` | Cerberus | 28/60 |  | Android/TrojanDropper.Agent.FOP trojan | Android:Evo-gen [Trj] | Android.BankBot.3313 | `classes.dex` (23) |
| `841e432a41b9625040704fd636d4fc3814a6d4193fa315cd78cfed9aa3991c04` | Coper | 28/64 | HEUR:Trojan-Banker.AndroidOS.Agent.ep | Android/Spy.Banker.CGX trojan | Android:Evo-gen [Trj] | Android.BankBot.Coper.13.origin | `classes.dex` (16)<br>`classes2.dex` (9)<br>`classes3.dex` (6) |
| `b9ddc7c5f9adbf012494ab258acd80ab35311b52e3b28f2a78a1d8dad75ab259` | Crocodilus | 28/67 | HEUR:Trojan-Banker.AndroidOS.Agent.eq | Android/TrojanDropper.Agent.MVV trojan | Android:Evo-gen [Trj] | Android.Packed.Sonj.3.origin | `classes.dex` (15) |
| `173192ec576111adbc0c228f75244cf627513c95ca1709036e9850f0cdb7c90b` | GhostRAT | 28/67 | HEUR:Trojan-Banker.AndroidOS.GhostNFC.i | Android/Spy.NGate.BX trojan | Android:Evo-gen [Trj] | Android.Banker.NGate.39.origin | `classes.dex` (21) |
| `a6ed100ae42e4fdabfd1b4c992762152bc4a11cc8e521b647b444c75bb7a9782` | GodFather | 28/65 | HEUR:Trojan-Banker.AndroidOS.GodFather.m | Android/Spy.Banker.BXU trojan | Android:Evo-gen [Trj] | Android.BankBot.GodFather.14.origin | `classes.dex` (12) |
| `49bc43a5b94d4a24f5561a98e3feac970fa37e9922a892f72351d5e94d77bc4c` | hydra | 28/67 | HEUR:Trojan-Downloader.AndroidOS.Banker.k | a variant of Android/TrojanDownloader.Agent.AAT | APK:RepMalware [Trj] | Android.DownLoader.1080.origin | `classes.dex` (20) |
| `c2bccfc8b3bdf2da5fb5c22055a9c4859256be7904933e9e0b92fa31fd0420d3` | GodFather | 28/67 | HEUR:Trojan-Banker.AndroidOS.GodFather.m | a variant of Android/Spy.Banker.BXU | Android:Evo-gen [Trj] | Android.BankBot.GodFather.3 | `classes.dex` (11) |
| `3745e0fb7edbdd8da57f44f5ee1d2b2cc0db5d7f8b63ea69ce12ce561402cf17` | SpinOK | 27/69 | not-a-virus:HEUR:AdWare.AndroidOS.TimeWaste.ah | Android/Spy.SpinOk.H trojan | Android:SpinOK-A [PUP] | Android.FakeApp.1147 | `classes5.dex` (8)<br>`classes2.dex` (2)<br>`73fc5b59ffb76b8ae9ef63f00bc302fe3d105661b05f58e67533aacd75685324` (2) |
| `801f956057aa608c7393b2fcca9b731c610c6bd5e14f4f3c1d64e8f211828319` | Crocodilus | 27/63 | HEUR:Trojan-Banker.AndroidOS.Agent.eq | Android/TrojanDropper.Agent.MVV trojan | Android:Evo-gen [Trj] | Android.Packed.Sonj.3.origin | `classes.dex` (13) |
| `fde931224d2e558e67ac8c9c0c1d0aac4f7562622a67870d6c3024bdeb851676` | TgToxic | 27/63 | HEUR:Trojan-Spy.AndroidOS.SpyNote.cb | a variant of Android/Spy.Banker.DFE | APK:RepMalware [Trj] | Android.BankBot.ToxicPanda.2.origin |  |
| `d0279f6afa15e29234f752229e9b91312fc118f1c73971a2042e163d586c3792` | Ermac | 26/65 | HEUR:Trojan-Dropper.AndroidOS.Banker.d | Android/TrojanDropper.Agent.LPD trojan | Android:Evo-gen [Trj] | Android.Packed.35.origin | `95efe46f0240173826975f93c97fd5dc62afd86276437dd88afdb9d36ff575e6` (15) |
| `a959108ec8f93ee4c71e588236788d17372f9d61b8f71a509a776f097889f36b` | FluBot | 26/67 | HEUR:Trojan-Dropper.AndroidOS.Agent.sl | a variant of Android/TrojanDropper.Agent.IVA | Android:Evo-gen [Trj] | Android.BankBot.10484 | `classes.dex` (20)<br>`AndroidManifest.xml` (3)<br>`resources.arsc` (1) |
| `8e39fb18e8acb2e4fc4bcd7db2efc320f5ec84100e8ba870fd24dd13a6584277` | PixRevolution | 26/62 | UDS:Trojan-Banker.AndroidOS.Agent.abd | Android/Agent.FOQ trojan | APK:RepMalware [Trj] | Android.Banker.1067.origin | `557c02b5e9ca8103e6ad5413df1b447fae5c9ce086a0b5330bf9c79a578585df.apk` (30)<br>`classes2.dex` (2) |
| `59e124084e9e269b3c1d8789c27b60323cfaff0b3118152caf7cdc042bd1b945` |  | 26/61 | HEUR:Trojan.AndroidOS.Boogr.gsh | Android/Agent.DHJ | APK:RepMalware [Trj] |  | `4fc5734235e3adc0cca431fc76c29058046fc32780c090885a1c3f85477f4136` (7) |
