#!/usr/bin/env python3
"""
Citrix NetScaler ADC / Gateway Version Detection Tool

Detects and fingerprints Citrix NetScaler versions using multiple techniques:
  1. GZIP timestamp fingerprinting of rdx_en.json.gz (fox-it/citrix-netscaler-triage)
  2. MD5 vhash fingerprinting of static resources
  3. EPA binary PE version extraction (kolbicz blog)
  4. Last-Modified header fingerprinting (telekom-security)
  5. Via: NS-CACHE header version extraction (WhatWeb/Nmap)
  6. Cneonction/nnCoection misspelled header detection (wafw00f)
  7. HTTP header analysis (NSC_ cookies, X-Citrix-*, Server)
  8. Favicon MD5 fingerprinting (rapid7/recog)
  9. Static file content hashing for cross-validation
  10. TLS certificate analysis (default Citrix cert, SANs)
  11. Endpoint probing and response parsing
  12. CVE vulnerability assessment against detected versions

Fingerprint database: 237 version entries from fox-it/citrix-netscaler-triage
Covers NetScaler 11.1 through 14.1 (2018-2025).

Usage:
    python3 citrix_detect.py <target_url>
    python3 citrix_detect.py --cve https://vpn.example.com

For authorized security assessments only.
"""

import argparse
import hashlib
import re
import ssl
import struct
import sys
import urllib3
from collections import OrderedDict, namedtuple
from datetime import datetime, timezone
from io import StringIO
import csv

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════════════
# FINGERPRINT DATABASE
# Source: fox-it/citrix-netscaler-triage (Apache 2.0)
# Format: rdx_en_date, rdx_en_stamp (unix), vhash (md5), version
# ═══════════════════════════════════════════════════════════════════════════
CITRIX_NETSCALER_VERSION_CSV = """\
rdx_en_date,rdx_en_stamp,vhash,version
2018-08-25 03:29:12+00:00,1535167752,,12.1-49.23
2018-10-16 17:54:20+00:00,1539712460,,12.1-49.37
2018-11-28 08:56:26+00:00,1543395386,26df0e65fba681faaeb333058a8b28bf,12.1-50.28
2019-01-18 17:41:34+00:00,1547833294,d3b5c691a4cfcc6769da8dc4e40f511d,12.1-50.31
2019-02-13 06:11:52+00:00,1550038312,1ffe249eccc42133689c145dc37d6372,unknown
2019-02-27 09:30:02+00:00,1551259802,995a76005c128f4e89474af12ac0de66,12.1-51.16
2019-03-25 22:37:08+00:00,1553553428,d2bd166fed66cdf035a0778a09fd688c,12.1-51.19
2019-04-19 11:04:22+00:00,1555671862,489cadbd8055b1198c9c7fa9d34921b9,unknown
2019-05-13 17:41:47+00:00,1557769307,86b4b2567b05dff896aae46d6e0765bc,13.0-36.27
2019-06-03 08:17:03+00:00,1559549823,73217f4753a74300c0a2ad762c6f1e65,unknown
2019-07-15 16:42:47+00:00,1563208967,dc8897f429a694d44934954b47118908,unknown
2019-09-10 07:54:45+00:00,1568102085,43a8abf580ea09a5fa8aa1bd579280b9,13.0-41.20
2019-09-16 22:22:54+00:00,1568672574,0705e646dc7f84d77e8e48561253be12,unknown
2019-10-07 10:37:28+00:00,1570444648,09a78a600b4fc5b9f581347604f70c0e,unknown
2019-10-11 13:24:36+00:00,1570800276,7116ed70ec000da9267a019728ed951e,13.0-41.28
2019-11-05 05:18:47+00:00,1572931127,8c62b39f7068ea2f3d3f7d40860c0cd4,12.1-55.13
2019-11-28 19:06:22+00:00,1574967982,fedb4ba86b5edcbc86081f2893dc9fdf,13.0-47.22
2020-01-16 13:36:04+00:00,1579181764,,11.1-63.15
2020-01-20 12:46:27+00:00,1579524387,02d30141fd053d5c3448bf04fbedb8d6,12.1-55.18
2020-01-20 13:09:05+00:00,1579525745,fd96bc8977256003de05ed84270b90bb,13.0-47.24
2020-02-28 14:27:56+00:00,1582900076,f787f9a8c05a502cd33f363e1e9934aa,12.1-55.24
2020-03-18 17:41:16+00:00,1584553276,b5fae8db23061679923e4b2a9b6c7a82,unknown
2020-03-19 17:40:43+00:00,1584639643,e79f3bbf822c1fede6b5a1a4b6035a41,13.0-52.24
2020-03-29 09:10:32+00:00,1585473032,f2db014a3eb9790a19dfd71331e7f5d0,12.1-56.22
2020-06-01 06:48:41+00:00,1590994121,fdf2235967556bad892fbf29ca69eefd,13.0-58.30
2020-06-01 15:16:27+00:00,1591024587,,12.0-63.21
2020-06-02 02:27:33+00:00,1591064853,,11.1-64.14
2020-06-09 19:06:55+00:00,1591729615,4ecb5abf6e4b1655c07386a2c958597c,12.1-57.18
2020-07-02 16:38:13+00:00,1593707893,dcb06155d51a0234e9d127658ef9f21f,13.0-58.32
2020-07-22 19:49:27+00:00,1595447367,12c4901ecc3677aad06f678be49cb837,13.0-61.48
2020-07-30 09:05:04+00:00,1596099904,bf898768ad1e1d477fa649711c72c6df,13.0-61.48
2020-08-14 14:54:04+00:00,1597416844,a1494e2e09cb96e424c6c66512224941,12.1-58.14
2020-09-01 11:47:01+00:00,1598960821,b1b38debf0e55c285c72465da3715034,12.1-58.15
2020-09-01 16:14:56+00:00,1598976896,06fbfcf525e47b5538f856965154e28c,13.0-64.35
2020-09-10 10:26:58+00:00,1599733618,,11.1-65.12
2020-09-22 01:21:45+00:00,1600737705,7a0c8874e93395c5e4f1ef3e5e600a25,12.1-59.16
2020-10-07 16:07:09+00:00,1602086829,a8e0eb4a1b3e157e0d3a5e57dc46fd35,13.0-67.39
2020-10-08 09:03:02+00:00,1602147782,0aef7f8e9ea2b528aa2073f2875a28b8,12.1-55.190
2020-11-04 10:14:41+00:00,1604484881,f1eb8548a4f1d4e565248d4db456fffe,12.1-60.16
2020-11-13 12:56:30+00:00,1605272190,e2444db11d0fa5ed738aa568c2630704,13.0-67.43
2020-11-22 13:29:18+00:00,1606051758,62eba0931b126b1558fea39fb466e588,unknown
2020-11-24 13:26:53+00:00,1606224413,3a65afd164db6f39aa41f5729001d257,13.0-67.43
2020-12-03 05:13:26+00:00,1606972406,9b545e2e4d153348bce08e3923cdfdc1,13.0-71.40
2020-12-26 19:04:08+00:00,1609009448,25ad60e92a33cbb5dbd7cd8c8380360d,13.0-71.44
2020-12-26 19:39:25+00:00,1609011565,0b516b768edfa45775c4be130c4b96b5,12.1-60.19
2021-01-04 03:07:45+00:00,1609729665,b3deb35b8a990a71acca052fd1e6e6e1,12.1-55.210
2021-01-06 09:43:42+00:00,1609926222,f0cc58ce7ec931656d9fcbfe50d37c4b,unknown
2021-02-02 13:36:06+00:00,1612272966,83e486e7ee7eb07ab88328a51466ac28,12.1-61.18
2021-02-18 18:37:49+00:00,1613673469,454d4ccdefa1d802a3f0ca474a2edd73,13.0-76.29
2021-03-08 17:23:41+00:00,1615224221,08ff522057b9422863dbabb104c7cf4b,12.1-61.19
2021-03-09 09:20:39+00:00,1615281639,648767678188e1567b7d15eee5714220,13.0-76.31
2021-03-11 15:46:10+00:00,1615477570,ce5da251414abbb1b6aed6d6141ed205,12.1-61.19
2021-04-05 14:13:22+00:00,1617632002,5e55889d93ff0f13c39bbebb4929a68e,13.0-79.64
2021-05-10 14:38:02+00:00,1620657482,35389d54edd8a7ef46dadbd00c1bc5ac,12.1-62.21
2021-05-12 11:36:11+00:00,1620819371,9f4514cd7d7559fa1fb28960b9a4c22d,unknown
2021-05-17 15:56:11+00:00,1621266971,8e4425455b9da15bdcd9d574af653244,12.1-62.23
2021-05-29 18:33:31+00:00,1622313211,,11.1-65.20
2021-05-31 14:05:18+00:00,1622469918,73952bdeead9629442cd391d64c74d93,13.0-82.41
2021-06-10 19:21:20+00:00,1623352880,25169dea48ef0f939d834468f3c626d2,13.0-82.42
2021-06-10 23:39:05+00:00,1623368345,efb9d8994f9656e476e80f9b278c5dae,12.1-62.25
2021-07-06 17:02:58+00:00,1625590978,affa5cd9f00480f144eda6334e03ec27,unknown
2021-07-07 01:45:38+00:00,1625622338,e1ebdcea7585d24e9f380a1c52a77f5d,12.1-62.27
2021-07-07 06:20:31+00:00,1625638831,,11.1-65.22
2021-07-16 16:45:56+00:00,1626453956,eb3f8a7e3fd3f44b70c121101618b80d,13.0-82.45
2021-09-10 07:31:30+00:00,1631259090,98a21b87cc25d486eb4189ab52cbc870,13.1-4.43
2021-09-27 14:01:20+00:00,1632751280,c9e95a96410b8f8d4bde6fa31278900f,13.0-83.27
2021-10-06 13:25:54+00:00,1633526754,394e3fa5ffce140c9dd4bedc38ddefa7,13.1-9.52
2021-10-12 11:53:46+00:00,1634039626,435b27d8f59f4b64a6beccb39ce06237,unknown
2021-10-12 18:49:09+00:00,1634064549,,11.1-65.23
2021-10-13 08:24:09+00:00,1634113449,f3d4041188d723fec4547b1942ffea93,12.1-63.22
2021-11-11 14:42:53+00:00,1636641773,158c7182df4973f1f5346e21e9d97a01,13.1-4.44
2021-11-11 17:02:35+00:00,1636650155,a66c02f4d04a1bd32bfdcc1655c73466,13.0-83.29
2021-11-11 20:06:47+00:00,1636661207,5cd6bd7d0aec5dd13a1afb603111733a,12.1-63.23
2021-11-17 15:43:23+00:00,1637163803,645bded68068748e3314ad3e3ec8eb8f,13.1-9.60
2021-11-26 05:41:16+00:00,1637905276,7277ec67fd822b7dae3399aa71786a0a,13.1-9.107
2021-12-08 13:14:05+00:00,1638969245,e8ff095e03a3efcff7ed851bfb9141e5,13.1-9.112
2021-12-10 16:17:15+00:00,1639153035,5112d5394de0cb5f6d474e032a708907,13.1-12.50
2021-12-10 18:48:29+00:00,1639162109,3a316d2de5362e9f76280b3157f48d08,13.0-84.10
2021-12-17 08:48:15+00:00,1639730895,bb71c656f6b4e0e1573c77c6536397c3,13.1-12.103
2021-12-22 09:54:58+00:00,1640166898,ee44bd3bc047aead57bc000097e3d8aa,12.1-63.24
2021-12-22 10:57:32+00:00,1640170652,13693866faf642734f0498eb45f73672,unknown
2021-12-22 15:18:49+00:00,1640186329,2b46554c087d2d5516559e9b8bc1875d,13.0-84.11
2021-12-23 08:28:43+00:00,1640248123,cf9d354b261231f6c6121058ba143af7,13.1-12.51
2022-01-20 02:36:41+00:00,1642646201,c6bcd2f119d83d1de762c8c09b482546,12.1-64.16
2022-01-28 06:22:15+00:00,1643350935,b3fb0319d5d2dad8c977b9986cc26bd8,12.1-55.265
2022-02-21 12:49:29+00:00,1645447769,0f3a063431972186f453e07954f34eb8,13.1-17.42
2022-02-23 07:02:10+00:00,1645599730,7364f85dc30b3d570015e04f90605854,unknown
2022-03-10 15:17:42+00:00,1646925462,e42d7b3cf4a6938aecebdae491ba140c,13.0-85.15
2022-03-25 20:49:02+00:00,1648241342,71ad6c771d99d846195b67c30bfb0433,13.1-12.117
2022-04-01 19:41:31+00:00,1648842091,310ffb5a44db3a14ed623394a4049ff9,unknown
2022-04-03 05:18:28+00:00,1648963108,2edf0f445b69b2e322e80dbc3f6f711c,12.1-55.276
2022-04-07 06:11:44+00:00,1649311904,b4ac9c8852a04234f38d73d1d8238d37,13.1-21.50
2022-04-21 07:34:34+00:00,1650526474,9f73637db0e0f987bf7825486bfb5efe,12.1-55.278
2022-04-21 10:38:48+00:00,1650537528,c212a67672ef2da5a74ecd4e18c25835,12.1-64.17
2022-04-22 19:18:31+00:00,1650655111,fbdc5fbaed59f858aad0a870ac4a779c,12.1-65.15
2022-05-09 12:54:41+00:00,1652100881,e24224ce907593aaadd243831b51dbd7,13.1-12.130
2022-05-19 08:10:13+00:00,1652947813,1884e7877a13a991b6d3fac01efbaf79,13.0-85.19
2022-05-26 12:51:09+00:00,1653569469,853edb55246c138c530839e638089036,13.1-24.38
2022-06-14 17:03:48+00:00,1655226228,7a45138b938a54ab056e0c35cf0ae56c,13.0-86.17
2022-06-29 13:46:08+00:00,1656510368,4434db1ec24dd90750ea176f8eab213c,12.1-65.17
2022-07-06 08:54:42+00:00,1657097682,469591a5ef8c69899320a319d5259922,12.1-55.282
2022-07-06 10:41:43+00:00,1657104103,adc1f7c850ca3016b21776467691a767,13.1-27.59
2022-07-12 19:52:59+00:00,1657655579,8f1767a6961f7b797d318d884dbb3a9c,13.1-12.131
2022-07-29 17:39:52+00:00,1659116392,1f63988aa4d3f6d835704be50c56788a,13.0-87.9
2022-08-24 14:57:01+00:00,1661353021,57d9f58db7576d6a194d7dd10888e354,13.1-30.52
2022-09-05 09:57:52+00:00,1662371872,8c6bef3b4f16d6c9bfc2913aae2535d1,13.1-30.103
2022-09-07 12:17:13+00:00,1662553033,f214d9aa6ff8f43fdb17ce81caac723f,13.1-30.105
2022-09-23 18:53:35+00:00,1663959215,7afe87a42140b566a2115d1e232fdc07,13.1-33.47
2022-09-27 12:31:22+00:00,1664281882,8cbccac1a96eee108ae3c85bf9ff845a,13.1-30.108
2022-09-30 04:47:01+00:00,1664513221,212fa0e7b3a5ca540f156caceba507fe,13.1-30.109
2022-10-04 12:03:35+00:00,1664885015,29adf2b509250b780bac083577c92b45,13.1-30.111
2022-10-04 16:11:03+00:00,1664899863,c1b64cea1b80e973580a73b787828daf,12.1-65.21
2022-10-12 07:25:44+00:00,1665559544,4d817946cef53571bc303373fd6b406b,12.1-55.289
2022-10-12 17:01:28+00:00,1665594088,aff0ad8c8a961d7b838109a7ee532bcb,13.1-33.49
2022-10-14 17:10:45+00:00,1665767445,37c10ac513599cf39997d52168432c0e,13.0-88.12
2022-10-31 15:54:59+00:00,1667231699,27292ddd74e24a311e4269de9ecaa6e7,13.0-88.13
2022-10-31 16:31:43+00:00,1667233903,5e939302a9d7db7e35e63a39af1c7bec,13.1-33.51
2022-11-03 05:22:05+00:00,1667452925,6e7b2de88609868eeda0b1baf1d34a7e,13.0-88.14
2022-11-03 05:38:29+00:00,1667453909,56672635f81a1ce1f34f828fef41d2fa,13.1-33.52
2022-11-11 04:16:21+00:00,1668140181,8ecc8331379bc60f49712c9b25f276ea,unknown
2022-11-11 06:00:31+00:00,1668146431,86c7421a034063574799dcd841ee88f0,unknown
2022-11-17 09:55:40+00:00,1668678940,9bf6d5d3131495969deba0f850447947,13.1-33.54
2022-11-17 10:37:18+00:00,1668681438,3bd7940b6425d9d4dba7e8b656d4ba65,13.0-88.16
2022-11-23 11:42:31+00:00,1669203751,0d656200c32bb47c300b81e599260c42,13.1-37.38
2022-11-28 11:55:05+00:00,1669636505,953fae977d4baedf39e83c9d1e134ef1,12.1-55.291
2022-11-30 11:42:25+00:00,1669808545,f063b04477adc652c6dd502ac0c39a75,12.1-65.25
2022-12-01 10:48:25+00:00,1669891705,c0c00b7caed367b1569574e4982294c5,13.1-30.114
2022-12-14 15:54:39+00:00,1671033279,14c6a775edda324764a940cfd3da48cb,13.0-89.7
2023-01-24 17:44:35+00:00,1674582275,c2b8537eb733844f1e0cc4f63210d016,13.0-90.7
2023-02-22 13:31:29+00:00,1677072689,b4c220db03ea18bc2eebb40e9ad3f4f8,13.1-42.47
2023-04-05 06:57:33+00:00,1680677853,0b2a3cb74b5c6adbe28827e8b76a9f64,12.1-55.296
2023-04-12 08:05:14+00:00,1681286714,6925fba74320b9bfb960299f7c3e7cce,13.1-45.61
2023-04-17 18:09:24+00:00,1681754964,cdb72bd7677da8af9942897256782c9b,13.1-37.150
2023-04-19 15:34:38+00:00,1681918478,281b46a105662de06fb259293aa79f2a,13.0-90.11
2023-04-26 11:42:55+00:00,1682509375,1487b55f253ea54b1d3603cc1212f164,13.1-45.62
2023-04-28 20:39:00+00:00,1682714340,a6a783263968040a97e44d7cac55eda6,12.1-65.35
2023-04-30 08:54:31+00:00,1682844871,d72c9f2af7ccded704862da7486cfef2,13.1-45.63
2023-05-12 04:49:56+00:00,1683866996,,13.0-91.12
2023-05-12 07:33:58+00:00,1683876838,14195083e08df261613408eb5cf3b212,13.1-45.64
2023-05-15 10:23:44+00:00,1684146224,4d63b52cc99fe712f9be5e4795c854e9,13.0-90.12
2023-06-03 07:35:50+00:00,1685777750,,13.1-48.47
2023-07-07 15:32:56+00:00,1688743976,,13.0-91.13
2023-07-07 16:15:10+00:00,1688746510,e72b4f05a103118667208783b57eee3b,unknown
2023-07-07 16:17:07+00:00,1688746627,46d83b1a2981c1cfefe8d3063adf78f4,13.1-37.159
2023-07-07 16:29:27+00:00,1688747367,28e592a607e8919cc6ca7dec63590e04,12.1-55.297
2023-07-10 01:57:59+00:00,1688954279,,13.1-49.101
2023-07-10 18:36:31+00:00,1689014191,,13.1-49.13
2023-07-11 07:14:37+00:00,1689059677,,13.1-49.102
2023-07-20 04:36:25+00:00,1689827785,,13.1-49.106
2023-07-28 00:25:01+00:00,1690503901,,14.1-4.42
2023-08-30 07:03:54+00:00,1693379034,,13.0-92.18
2023-09-15 06:40:36+00:00,1694760036,,14.1-8.50
2023-09-21 05:25:24+00:00,1695273924,,13.0-92.19
2023-09-21 06:17:01+00:00,1695277021,,13.1-49.15
2023-09-21 08:15:02+00:00,1695284102,e1aa8ba6d7e558d43f0369d9b81cbb1c,12.1-65.37
2023-09-21 17:12:48+00:00,1695316368,155a75fb7efac3347e7362fd23083aa5,12.1-55.300
2023-09-27 12:27:52+00:00,1695817672,,13.1-37.164
2023-10-18 07:27:04+00:00,1697614024,,13.1-50.23
2023-11-22 18:19:39+00:00,1700677179,,14.1-12.30
2023-12-06 18:15:43+00:00,1701886543,,14.1-8.120
2023-12-08 11:31:08+00:00,1702035068,,14.1-12.34
2023-12-08 19:10:40+00:00,1702062640,,13.1-51.14
2023-12-14 10:12:36+00:00,1702548756,,13.0-92.21
2023-12-15 07:26:58+00:00,1702625218,,13.1-51.15
2023-12-15 09:18:34+00:00,1702631914,,14.1-12.35
2023-12-18 07:59:52+00:00,1702886392,f6beac6ccd073f5f7c1a64c4c7e24c7e,12.1-55.302
2023-12-18 14:16:04+00:00,1702908964,9debca402a9fae56a0d5e0979f685cf2,12.1-65.39
2024-01-02 11:24:56+00:00,1704194696,,14.1-8.122
2024-01-05 04:15:53+00:00,1704428153,,13.1-37.176
2024-02-08 05:34:51+00:00,1707370491,,14.1-17.38
2024-02-29 17:31:08+00:00,1709227868,,13.1-52.19
2024-04-18 21:13:30+00:00,1713474810,,14.1-21.57
2024-04-26 11:56:34+00:00,1714132594,08604a97f08f6973502adb8ebf78e0b0,12.1-55.304
2024-05-01 05:48:44+00:00,1714542524,fe1071e2b14a5b5016d3eb57ddcfc86d,12.1-55.304
2024-05-13 16:45:28+00:00,1715618728,,13.1-53.17
2024-05-14 12:55:51+00:00,1715691351,,13.1-37.183
2024-06-08 07:28:50+00:00,1717831730,,14.1-25.53
2024-06-12 18:00:57+00:00,1718215257,c9d805972fbf558cf7a229db44632fa7,12.1-55.307
2024-06-14 10:47:34+00:00,1718362054,,13.1-37.188
2024-06-24 12:44:20+00:00,1719233060,,14.1-25.107
2024-07-04 10:41:15+00:00,1720089675,,13.0-92.31
2024-07-04 14:32:40+00:00,1720103560,,13.1-53.24
2024-07-04 16:31:28+00:00,1720110688,,14.1-25.56
2024-07-04 16:49:33+00:00,1720111773,,13.1-37.190
2024-07-05 06:07:38+00:00,1720159658,,14.1-25.108
2024-07-08 18:53:11+00:00,1720464791,,13.0-92.31
2024-07-08 21:21:59+00:00,1720473719,550d960eff41e3a6342b95c7ad149148,12.1-55.309
2024-07-17 17:53:35+00:00,1721238815,,13.1-54.29
2024-08-08 10:59:41+00:00,1723114781,,14.1-29.63
2024-08-13 11:43:40+00:00,1723549420,,13.1-37.199
2024-09-16 12:13:19+00:00,1726488799,,13.1-55.29
2024-10-07 20:11:28+00:00,1728331888,,13.1-37.207
2024-10-07 20:55:33+00:00,1728334533,a7c411815373059b33b4d83bed6145a2,12.1-55.321
2024-10-11 10:23:04+00:00,1728642184,,14.1-29.72
2024-10-21 20:52:15+00:00,1729543935,0dd3f401dd33679f07e06961db10a298,12.1-55.321
2024-10-22 01:37:14+00:00,1729561034,,14.1-34.42
2024-10-24 13:43:49+00:00,1729777429,,13.1-55.34
2024-10-29 06:55:25+00:00,1730184925,,14.1-34.101
2024-11-07 16:17:10+00:00,1730996230,,13.1-56.18
2024-11-29 10:21:03+00:00,1732875663,,13.1-37.219
2024-12-16 17:20:08+00:00,1734369608,,14.1-38.53
2025-01-25 10:12:49+00:00,1737799969,,13.1-57.26
2025-02-11 01:19:25+00:00,1739236765,c624dcce8d3355d555021d2aac5f9715,12.1-55.325
2025-02-18 01:07:57+00:00,1739840877,423fd15327ae1326fd97733652441907,12.1-55.325
2025-02-21 16:41:24+00:00,1740156084,,14.1-43.50
2025-03-06 13:19:10+00:00,1741267150,,14.1-34.105
2025-03-14 09:32:59+00:00,1741944779,,14.1-34.107
2025-04-01 08:43:29+00:00,1743497009,,13.1-37.232
2025-04-08 14:08:19+00:00,1744121299,,13.1-58.21
2025-04-09 07:52:44+00:00,1744185164,,14.1-43.109
2025-05-13 17:58:16+00:00,1747159096,,14.1-47.40
2025-05-20 07:48:42+00:00,1747727322,,14.1-47.43
2025-05-21 08:05:34+00:00,1747814734,,14.1-47.44
2025-06-07 13:53:15+00:00,1749304395,,14.1-47.46
2025-06-10 10:53:47+00:00,1749552827,,14.1-43.56
2025-06-10 14:02:25+00:00,1749564145,89929af92ff35a042d78e9010b7ec534,12.1-55.328
2025-06-10 16:26:42+00:00,1749572802,,13.1-37.235
2025-06-10 20:52:27+00:00,1749588747,,13.1-58.32
2025-06-17 04:21:23+00:00,1750134083,f069136a9297a52b6d86a5de987d9323,12.1-55.328
2025-06-18 13:04:11+00:00,1750251851,,13.1-59.19
2025-08-20 12:21:05+00:00,1755692465,765c645f7af4a1ef5c11d464fafc6244,12.1-55.330
2025-08-20 12:23:35+00:00,1755692615,,14.1-47.48
2025-08-20 12:35:34+00:00,1755693334,,13.1-37.241
2025-08-20 12:44:46+00:00,1755693886,,13.1-59.22
2025-08-26 02:22:30+00:00,1756174950,a53b1af56a97019171ec39665fedc54a,12.1-55.330
2025-09-02 07:11:47+00:00,1756797107,,14.1-51.72
2025-09-03 15:24:16+00:00,1756913056,,13.1-60.26
2025-09-03 21:18:16+00:00,1756934296,,13.1-37.246
2025-09-17 13:00:17+00:00,1758114017,,13.1-37.247
2025-09-21 18:58:07+00:00,1758481087,,13.1-60.29
2025-09-22 20:27:08+00:00,1758572828,,14.1-51.80
2025-10-15 17:27:40+00:00,1760549260,,14.1-56.71
2025-10-31 09:51:19+00:00,1761904279,,13.1-37.250
2025-10-31 18:39:40+00:00,1761935980,,13.1-60.32
2025-11-09 02:30:07+00:00,1762655407,,14.1-56.74
2025-11-09 04:45:20+00:00,1762663520,,13.1-61.23
2025-11-11 03:01:37+00:00,1762830097,11ba0524227f5450bc03fb70ed17c3d5,12.1-55.333
"""

# ═══════════════════════════════════════════════════════════════════════════
# LAST-MODIFIED HEADER FINGERPRINTS (telekom-security/cve-2023-3519-citrix-scanner)
# ═══════════════════════════════════════════════════════════════════════════
LAST_MODIFIED_FINGERPRINTS = {
    "Fri, 07 Jul 2023 15:39:40 GMT": "13.0-91.13",
    "Mon, 10 Jul 2023 17:41:17 GMT": "13.1-49.13",
    "Mon, 10 Jul 2023 18:36:14 GMT": "13.1-49.13",
}

# ═══════════════════════════════════════════════════════════════════════════
# FAVICON MD5 DATABASE (rapid7/recog)
# ═══════════════════════════════════════════════════════════════════════════
FAVICON_MD5 = {
    "871eb7d317524611af4f05c6ba878df8": "Citrix NetScaler",
    "4eaaa139063e6706d1b5d0eee833d47b": "Citrix NetScaler Gateway",
    "953e0d0190e50d247f4ece5620569ef1": "Citrix NetScaler SDX Gateway",
    "52794c5e8a69a8b03ba891e24c39da65": "Citrix NetScaler SDX Gateway",
    "f097f0adf2b9e95a972d21e5e5ab746d": "Citrix Access Server",
    "9939a032a9845e4d931d14e08f5a6c7c": "Citrix XenApp Logon",
}

# ═══════════════════════════════════════════════════════════════════════════
# VERSION PARSING & CVE LOGIC
# ═══════════════════════════════════════════════════════════════════════════
VersionTuple = namedtuple("VersionTuple", ["major", "minor", "build", "patch"])


def parse_version(version_str: str) -> VersionTuple | None:
    """Parse '14.1-47.48' into VersionTuple(14, 1, 47, 48)."""
    if not version_str or version_str == "unknown":
        return None
    try:
        parts = version_str.replace(".", "-").split("-")
        return VersionTuple(*(int(p) for p in parts[:4]))
    except (ValueError, TypeError):
        return None


def is_fips_13_1(vt: VersionTuple) -> bool:
    return vt.major == 13 and vt.minor == 1 and vt.build == 37


def is_fips_12_1(vt: VersionTuple) -> bool:
    return vt.major == 12 and vt.minor == 1 and vt.build == 55


def is_eol(vt: VersionTuple) -> bool:
    if is_fips_13_1(vt) or is_fips_12_1(vt):
        return False
    if vt.major == 13 and vt.minor == 0:
        return True
    if vt.major <= 12:
        return True
    return False


# CVE check functions (from fox-it/citrix-netscaler-triage)
def is_vuln_ctx693420(vt: VersionTuple) -> bool:
    """CVE-2025-5349 / CVE-2025-5777 (CitrixBleed 2) - CTX693420"""
    if is_eol(vt):
        return True
    if vt.major == 14:
        return vt < VersionTuple(14, 1, 43, 56)
    if is_fips_13_1(vt):
        return vt < VersionTuple(13, 1, 37, 235)
    if vt.major == 13 and vt.minor == 1:
        return vt < VersionTuple(13, 1, 58, 32)
    if is_fips_12_1(vt):
        return vt < VersionTuple(12, 1, 55, 328)
    return True


def is_vuln_ctx694788(vt: VersionTuple) -> bool:
    """CVE-2025-6543 (memory overflow, exploited in-the-wild) - CTX694788"""
    if is_eol(vt):
        return True
    if vt.major == 14:
        return vt < VersionTuple(14, 1, 47, 46)
    if is_fips_13_1(vt):
        return vt < VersionTuple(13, 1, 37, 236)
    if vt.major == 13 and vt.minor == 1:
        return vt < VersionTuple(13, 1, 59, 19)
    if is_fips_12_1(vt):
        return False  # 12.1 FIPS not affected
    return True


def is_vuln_ctx694938(vt: VersionTuple) -> bool:
    """CVE-2025-7775 / CVE-2025-7776 / CVE-2025-8424 - CTX694938"""
    if is_eol(vt):
        return True
    if vt.major == 14:
        return vt < VersionTuple(14, 1, 47, 48)
    if is_fips_13_1(vt):
        return vt < VersionTuple(13, 1, 37, 241)
    if vt.major == 13 and vt.minor == 1:
        return vt < VersionTuple(13, 1, 59, 22)
    if is_fips_12_1(vt):
        return vt < VersionTuple(12, 1, 55, 330)
    return True


CVE_CHECKS = {
    "CVE-2025-5349": ("CTX693420 - CitrixBleed 2 (memory disclosure)", is_vuln_ctx693420),
    "CVE-2025-5777": ("CTX693420 - CitrixBleed 2 (memory disclosure)", is_vuln_ctx693420),
    "CVE-2025-6543": ("CTX694788 - Memory overflow (exploited in-the-wild)", is_vuln_ctx694788),
    "CVE-2025-7775": ("CTX694938 - Multiple vulnerabilities", is_vuln_ctx694938),
    "CVE-2025-7776": ("CTX694938 - Multiple vulnerabilities", is_vuln_ctx694938),
    "CVE-2025-8424": ("CTX694938 - Multiple vulnerabilities", is_vuln_ctx694938),
}

# ═══════════════════════════════════════════════════════════════════════════
# BUILD FINGERPRINT DATABASE LOADER
# ═══════════════════════════════════════════════════════════════════════════

def load_fingerprint_db():
    """Parse the embedded CSV into lookup dictionaries."""
    vstamp_to_version = {}
    vhash_to_version = {}

    reader = csv.DictReader(StringIO(CITRIX_NETSCALER_VERSION_CSV))
    for row in reader:
        stamp = int(row["rdx_en_stamp"])
        version = row["version"]
        vstamp_to_version[stamp] = version

        vhash = row["vhash"].strip()
        if vhash and version != "unknown":
            vhash_to_version[vhash] = version

    return vstamp_to_version, vhash_to_version


VSTAMP_TO_VERSION, VHASH_TO_VERSION = load_fingerprint_db()

# ═══════════════════════════════════════════════════════════════════════════
# REGEX PATTERNS & ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

VERSION_PATTERNS = [
    re.compile(r"(?:Citrix|NetScaler|NS)[\w\s-]*?(\d{1,2}\.\d[\w.-]+)", re.I),
    re.compile(r"Version[:\s]*(\d{1,2}\.\d+[\w.-]+)", re.I),
    re.compile(r'"version"\s*:\s*"(\d{1,2}\.\d+[\w.-]+)"', re.I),
    re.compile(r"build[:\s]+(\d{1,2}\.\d+[\w.-]+)", re.I),
    re.compile(r"ns-(\d{1,2}\.\d+[\w.-]+)", re.I),
    re.compile(r'rec_build="([^"]+)"', re.I),
    re.compile(r'version="([^"]+)"', re.I),
    re.compile(r"nsversion\s*=\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"CTXS\.Version\s*=\s*['\"]([^'\"]+)['\"]", re.I),
]

PROBE_ENDPOINTS = OrderedDict([
    ("/logon/LogonPoint/index.html", "StoreFront / Gateway Login Page"),
    ("/vpn/index.html", "Gateway VPN Login Page"),
    ("/vpn/pluginlist.xml", "VPN Plugin List (version in XML attributes)"),
    ("/epa/epa.html", "Endpoint Analysis Page"),
    ("/nf/auth/doAuthentication.do", "Authentication Endpoint"),
    ("/vpn/js/rdx/core/lang/rdx-en.json", "RDX Localization JSON"),
    ("/menu/ss", "Menu Resource (legacy)"),
    ("/menu/neo", "Menu Resource (modern)"),
    ("/menu/guiw", "GUI Wizard Resource"),
    ("/gwtest/SecurityTest.png", "Gateway Security Test Resource"),
    ("/vpn/media/citrix_gateway_logo.png", "Gateway Logo (presence = Citrix)"),
])


# ═══════════════════════════════════════════════════════════════════════════
# DETECTOR CLASS
# ═══════════════════════════════════════════════════════════════════════════

class CitrixDetector:
    def __init__(self, target: str, timeout: int = 10, user_agent: str | None = None,
                 check_cves: bool = False):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.check_cves = check_cves
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self.findings: list[dict] = []
        self.versions_found: set[str] = set()
        self.is_citrix = False
        self.gzip_version: str | None = None  # highest-confidence version
        self.gzip_stamp: int | None = None  # raw GZIP MTIME even if not in DB
        self.gzip_date: str | None = None  # formatted date of GZIP MTIME

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _get(self, path: str, stream: bool = False) -> requests.Response | None:
        url = f"{self.target}{path}"
        try:
            return self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True, stream=stream)
        except requests.RequestException as exc:
            self._log(f"  [-] {path}: connection error ({type(exc).__name__})")
            return None

    @staticmethod
    def _log(msg: str):
        print(msg)

    def _add_finding(self, source: str, detail: str, version: str | None = None):
        finding = {"source": source, "detail": detail, "version": version}
        self.findings.append(finding)
        if version and version != "unknown":
            self.versions_found.add(version)

    def _extract_versions(self, text: str) -> list[str]:
        versions = []
        for pattern in VERSION_PATTERNS:
            for match in pattern.finditer(text):
                v = match.group(1).strip()
                if v and len(v) >= 3:
                    versions.append(v)
        return versions

    # ------------------------------------------------------------------
    # Detection: GZIP Timestamp Fingerprinting (primary technique)
    # ------------------------------------------------------------------
    def check_gzip_fingerprint(self):
        """Fetch rdx_en.json.gz and extract the GZIP MTIME timestamp."""
        path = "/vpn/js/rdx/core/lang/rdx_en.json.gz"

        # Many NetScalers apply Content-Encoding: gzip on top of the .gz file,
        # causing requests to transparently decompress it and lose the GZIP header.
        # We use stream=True and resp.raw.read() with decode_content=False to
        # get the raw bytes before any Content-Encoding decompression.
        url = f"{self.target}{path}"
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True,
                                    stream=True)
        except requests.RequestException as exc:
            self._log(f"  [-] {path}: connection error ({type(exc).__name__})")
            return

        if resp.status_code != 200:
            self._log(f"  [-] {path} -> HTTP {resp.status_code}")
            return

        # Read raw undecoded bytes — bypasses Content-Encoding decompression
        data = resp.raw.read(decode_content=False)
        if len(data) < 16:
            self._log(f"  [-] {path} -> response too small ({len(data)} bytes)")
            return

        # Validate GZIP header: magic + deflate + FNAME flag
        if not data.startswith(b"\x1f\x8b\x08\x08"):
            self._log(f"  [-] {path} -> not a valid GZIP with FNAME field")
            return

        # Verify original filename is rdx_en.json
        if b"rdx_en.json" not in data[:100]:
            self._log(f"  [-] {path} -> GZIP filename mismatch")
            return

        self.is_citrix = True

        # Extract MTIME (bytes 4-8, little-endian uint32)
        stamp = struct.unpack("<I", data[4:8])[0]
        dt = datetime.fromtimestamp(stamp, tz=timezone.utc)
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Always record the stamp — useful even when not in DB
        self.gzip_stamp = stamp
        self.gzip_date = dt_str

        version = VSTAMP_TO_VERSION.get(stamp, None)

        if version and version != "unknown":
            self.gzip_version = version
            self._add_finding(
                "GZIP timestamp (rdx_en.json.gz)",
                f"MTIME={stamp} ({dt_str}) -> {version}",
                version,
            )
            self._log(f"  [+] {path} -> GZIP MTIME fingerprint: {version} ({dt_str})")
        elif version == "unknown":
            self._add_finding(
                "GZIP timestamp (rdx_en.json.gz)",
                f"MTIME={stamp} ({dt_str}) -> timestamp in DB but version unknown",
            )
            self._log(f"  [~] {path} -> known timestamp but unmapped version ({dt_str})")
        else:
            self._add_finding(
                "GZIP timestamp (rdx_en.json.gz)",
                f"MTIME={stamp} ({dt_str}) -> not in fingerprint database",
            )
            self._log(f"  [~] {path} -> GZIP timestamp not in DB ({dt_str}, stamp={stamp})")

        # Also try vhash (MD5 of full response body)
        md5 = hashlib.md5(data).hexdigest()
        vhash_version = VHASH_TO_VERSION.get(md5)
        if vhash_version:
            self._add_finding(
                "vhash MD5 (rdx_en.json.gz)",
                f"MD5={md5} -> {vhash_version}",
                vhash_version,
            )
            self._log(f"  [+] {path} -> vhash MD5 match: {vhash_version}")
            if not self.gzip_version:
                self.gzip_version = vhash_version

    # ------------------------------------------------------------------
    # Detection: Last-Modified Header Fingerprinting
    # ------------------------------------------------------------------
    def check_last_modified(self, resp: requests.Response, path: str):
        """Check Last-Modified header against known patched timestamps."""
        lm = resp.headers.get("Last-Modified", "")
        if not lm:
            return
        version = LAST_MODIFIED_FINGERPRINTS.get(lm)
        if version:
            self.is_citrix = True
            self._add_finding(
                f"Last-Modified ({path})",
                f"'{lm}' matches known patched build",
                version,
            )

    # ------------------------------------------------------------------
    # Detection: HTTP Headers
    # ------------------------------------------------------------------
    def check_headers(self, resp: requests.Response, path: str):
        headers = resp.headers

        # NSC_ cookies (NetScaler load-balancer)
        for cookie in resp.cookies:
            if cookie.name.startswith("NSC_"):
                self.is_citrix = True
                self._add_finding(f"Cookie ({path})",
                                  f"NetScaler cookie: {cookie.name}")

        # X-Citrix / X-NetScaler headers
        for hdr, val in headers.items():
            hl = hdr.lower()
            if "citrix" in hl or "netscaler" in hl:
                self.is_citrix = True
                self._add_finding(f"Header ({path})", f"{hdr}: {val}")
                for v in self._extract_versions(val):
                    self._add_finding(f"Header version ({path})", f"{hdr} -> {v}", v)

        # Server header
        server = headers.get("Server", "")
        if server:
            for kw in ("Citrix", "NetScaler", "NS-CACHE"):
                if kw.lower() in server.lower():
                    self.is_citrix = True
                    self._add_finding(f"Server header ({path})", server)
                    break

        # CSP / X-Frame-Options referencing Citrix
        for hdr_name in ("X-Frame-Options", "Content-Security-Policy"):
            val = headers.get(hdr_name, "")
            if "citrix" in val.lower() or "netscaler" in val.lower():
                self.is_citrix = True
                self._add_finding(f"{hdr_name} ({path})", val)

        self.check_last_modified(resp, path)
        self.check_via_header(resp, path)
        self.check_misspelled_headers(resp, path)

    # ------------------------------------------------------------------
    # Detection: Body Analysis
    # ------------------------------------------------------------------
    def check_body_versions(self, text: str, path: str):
        for v in self._extract_versions(text):
            self._add_finding(f"Body pattern ({path})", f"Version string: {v}", v)

    def check_body_indicators(self, text: str, path: str):
        indicators = [
            ("Citrix Gateway", "Citrix Gateway reference"),
            ("NetScaler", "NetScaler reference"),
            ("Citrix ADC", "Citrix ADC reference"),
            ("StoreFront", "Citrix StoreFront reference"),
            ("XenApp", "Citrix XenApp reference"),
            ("XenDesktop", "Citrix XenDesktop reference"),
            ("Citrix Receiver", "Citrix Receiver reference"),
            ("Citrix Workspace", "Citrix Workspace reference"),
            ("CTXS.", "Citrix JavaScript namespace"),
            ("ctxs_", "Citrix CSS/JS prefix"),
            ("/vpn/", "Citrix VPN path reference"),
            ("/logon/LogonPoint", "Citrix LogonPoint reference"),
        ]
        for keyword, desc in indicators:
            if keyword.lower() in text.lower():
                self.is_citrix = True
                self._add_finding(f"Indicator ({path})", desc)

    def check_title_tag(self, text: str, path: str):
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if m:
            title = m.group(1).strip()
            if title:
                citrix_keywords = ["citrix", "netscaler", "gateway", "storefront"]
                if any(k in title.lower() for k in citrix_keywords):
                    self.is_citrix = True
                    self._add_finding(f"Page title ({path})", title)

    # ------------------------------------------------------------------
    # Detection: vhash extraction from HTML (securekomodo/citrixInspector)
    # ------------------------------------------------------------------
    def check_index_vhash(self, text: str, path: str):
        """Extract ?v=<MD5> cache-busting hash from index.html resources."""
        for m in re.finditer(r'\?v=([0-9a-f]{32})', text, re.I):
            vhash = m.group(1).lower()
            version = VHASH_TO_VERSION.get(vhash)
            if version:
                self.is_citrix = True
                self._add_finding(
                    f"vhash from HTML ({path})",
                    f"?v={vhash} -> {version}",
                    version,
                )
                self._log(f"  [+] {path} -> vhash match in HTML: {version}")
                if not self.gzip_version:
                    self.gzip_version = version
                return  # one match is enough

    # ------------------------------------------------------------------
    # Detection: pluginlist.xml EPA plugin version
    # ------------------------------------------------------------------
    def check_pluginlist_epa(self, text: str, path: str):
        """Parse EPA plugin version from pluginlist.xml for vuln heuristic."""
        m = re.search(
            r'<plugin\s+name="Netscaler Gateway EPA plug-in[^"]*"[^>]*'
            r'version="([^"]+)"', text, re.I
        )
        if not m:
            return
        epa_ver = m.group(1)
        self._add_finding(f"EPA plugin ({path})", f"EPA plugin version: {epa_ver}")
        try:
            parts = epa_ver.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            if major < 22:
                self._add_finding(f"EPA heuristic ({path})",
                                  f"EPA major={major} < 22: likely vulnerable to CVE-2023-3519")
            elif major >= 23 and minor >= 5:
                self._add_finding(f"EPA heuristic ({path})",
                                  f"EPA {major}.{minor}: likely patched for CVE-2023-3519")
        except (ValueError, IndexError):
            pass

    # ------------------------------------------------------------------
    # Detection: EPA binary PE version extraction (kolbicz blog 2015)
    # ------------------------------------------------------------------
    def check_epa_binary(self):
        """Download EPA setup binary and extract version metadata.

        The EPA binary is often an NSIS installer. We search for all
        VS_VERSION_INFO structures and look for Citrix/NetScaler/nsepa
        product names to find the correct one (ignoring bundled components
        like Internet Explorer).
        """
        for path in ("/epa/scripts/win/nsepa_setup.exe",
                     "/epa/scripts/win/nsepa_setup64.exe"):
            resp = self._get(path, stream=True)
            if resp is None or resp.status_code != 200:
                continue

            # Get total file size from Content-Length
            total_size = int(resp.headers.get("Content-Length", 0))
            resp.close()

            if total_size < 64:
                continue

            self.is_citrix = True
            self._log(f"  [+] {path} -> EPA binary accessible ({total_size} bytes)")

            # Search chunks of the PE for Citrix version info.
            # NSIS installers have the real version info in the first ~2MB
            # or in the resource section near the end.
            chunks_to_search = [
                ("first 2MB", 0, min(total_size, 2 * 1024 * 1024)),
            ]
            if total_size > 2 * 1024 * 1024:
                tail_start = max(0, total_size - 512 * 1024)
                chunks_to_search.append(("last 512KB", tail_start, total_size))

            for desc, start, end in chunks_to_search:
                try:
                    r2 = self.session.get(
                        f"{self.target}{path}", timeout=self.timeout,
                        headers={"Range": f"bytes={start}-{end - 1}"},
                        stream=True,
                    )
                    data = r2.raw.read(decode_content=True)
                    r2.close()
                except requests.RequestException:
                    continue

                if self._extract_epa_version(data, path):
                    return  # found it

    def _extract_epa_version(self, data: bytes, path: str) -> bool:
        """Search binary data for Citrix-specific PE version info."""
        # Find all VS_VERSION_INFO occurrences
        marker = b"V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00"
        search_start = 0

        while True:
            idx = data.find(marker, search_start)
            if idx == -1:
                break
            search_start = idx + len(marker)

            # Check if this version block is Citrix-related by looking for
            # product name strings nearby (within ~2KB after the marker)
            region = data[idx:idx + 2048]
            citrix_labels = [
                b"C\x00i\x00t\x00r\x00i\x00x\x00",
                b"N\x00e\x00t\x00S\x00c\x00a\x00l\x00e\x00r\x00",
                b"n\x00s\x00e\x00p\x00a\x00",
                b"E\x00P\x00A\x00",
            ]
            is_citrix_block = any(lbl in region for lbl in citrix_labels)

            # Extract FileVersion string
            for lbl_name, lbl_bytes in [
                ("FileVersion", b"F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00"),
                ("ProductVersion", b"P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00"),
            ]:
                li = data.find(lbl_bytes, idx, idx + 2048)
                if li == -1:
                    continue
                s = li + len(lbl_bytes)
                while s < len(data) - 1 and data[s:s+2] == b"\x00\x00":
                    s += 2
                e = s
                while e < len(data) - 1 and data[e:e+2] != b"\x00\x00":
                    e += 2
                try:
                    ver_str = data[s:e].decode("utf-16-le").strip("\x00").strip()
                except (UnicodeDecodeError, ValueError):
                    continue

                if not ver_str or not re.match(r"[\d.,\- ]+", ver_str):
                    continue

                if is_citrix_block:
                    # Extract product name for context
                    pn_bytes = b"P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00"
                    pi = data.find(pn_bytes, idx, idx + 2048)
                    prod_name = ""
                    if pi >= 0:
                        ps = pi + len(pn_bytes)
                        while ps < len(data) - 1 and data[ps:ps+2] == b"\x00\x00":
                            ps += 2
                        pe = ps
                        while pe < len(data) - 1 and data[pe:pe+2] != b"\x00\x00":
                            pe += 2
                        try:
                            prod_name = data[ps:pe].decode("utf-16-le").strip("\x00").strip()
                        except (UnicodeDecodeError, ValueError):
                            pass

                    detail = f"EPA {lbl_name}: {ver_str}"
                    if prod_name:
                        detail += f" ({prod_name})"
                    self._add_finding(f"EPA binary ({path})", detail, ver_str)
                    self._log(f"  [+] {path} -> {detail}")
                    return True

        return False

    # ------------------------------------------------------------------
    # Detection: Via NS-CACHE header (WhatWeb, Nmap, wafw00f)
    # ------------------------------------------------------------------
    def check_via_header(self, resp: requests.Response, path: str):
        """Extract version from Via: NS-CACHE-X.X header."""
        via = resp.headers.get("Via", "")
        if "NS-CACHE" in via.upper():
            self.is_citrix = True
            self._add_finding(f"Via header ({path})", f"Via: {via}")
            m = re.search(r"NS-CACHE-(\d+\.\d+)", via, re.I)
            if m:
                ver = m.group(1)
                self._add_finding(
                    f"Via NS-CACHE version ({path})",
                    f"Major.minor version from cache header: {ver}",
                    ver,
                )

    # ------------------------------------------------------------------
    # Detection: Cneonction/nnCoection misspelled headers (Nmap, wafw00f)
    # ------------------------------------------------------------------
    def check_misspelled_headers(self, resp: requests.Response, path: str):
        """Detect NetScaler's client keep-alive header mangling."""
        for hdr_name in ("Cneonction", "nnCoection"):
            if hdr_name in resp.headers:
                self.is_citrix = True
                self._add_finding(
                    f"Misspelled header ({path})",
                    f"{hdr_name}: {resp.headers[hdr_name]} (NetScaler keep-alive signature)",
                )

    # ------------------------------------------------------------------
    # Detection: Favicon MD5 matching (rapid7/recog)
    # ------------------------------------------------------------------
    def check_favicon(self):
        """Check favicon against known Citrix favicon hashes."""
        for path in ("/favicon.ico",
                     "/vpn/images/AccessGateway.ico",
                     "/vpn/images/gateway.ico"):
            resp = self._get(path)
            if resp is None or resp.status_code != 200:
                continue
            md5 = hashlib.md5(resp.content).hexdigest()
            product = FAVICON_MD5.get(md5)
            size = len(resp.content)
            if product:
                self.is_citrix = True
                self._add_finding(
                    f"Favicon ({path})",
                    f"MD5={md5} ({size} bytes) -> {product}",
                )
                self._log(f"  [+] {path} -> favicon match: {product} (MD5={md5})")
            elif size > 0 and resp.content[:4] == b"\x00\x00\x01\x00":
                # Valid ICO file but unknown hash — record for future DB building
                self._add_finding(
                    f"Favicon ({path})",
                    f"Unknown ICO: MD5={md5}, {size} bytes",
                )

    # ------------------------------------------------------------------
    # Detection: Static file content hashing (cross-validation)
    # ------------------------------------------------------------------
    def check_static_file_hashes(self):
        """Hash key static files for version cross-validation."""
        files = [
            "/vpn/js/gateway_login_view.js",
            "/vpn/js/gateway_login_form_view.js",
            "/logon/LogonPoint/receiver/js/ctxs.core.min.js",
            "/logon/LogonPoint/receiver/js/ctxs.webui.min.js",
        ]
        for path in files:
            resp = self._get(path)
            if resp is None or resp.status_code != 200:
                continue
            md5 = hashlib.md5(resp.content).hexdigest()
            size = len(resp.content)
            self._add_finding(
                f"Static file hash ({path})",
                f"MD5={md5}, {size} bytes",
            )

    # ------------------------------------------------------------------
    # Detection: Default TLS certificate (rapid7/recog)
    # ------------------------------------------------------------------
    def check_tls_cert(self):
        """Check for default NetScaler TLS certificate and extract SANs."""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(ssl.socket(), server_hostname=host) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                cert_der = s.getpeercert(binary_form=True)
                cert = s.getpeercert()
        except Exception:
            return

        # Check for default Citrix cert subject
        if cert:
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))

            org = subject.get("organizationName", "")
            ou = subject.get("organizationalUnitName", "")
            if "Citrix" in org or "NS Internal" in ou:
                self.is_citrix = True
                self._add_finding(
                    "TLS certificate",
                    f"Default Citrix cert: O={org}, OU={ou}",
                )

            # Extract SANs for context
            sans = cert.get("subjectAltName", ())
            san_list = [v for _, v in sans]
            if san_list:
                self._add_finding(
                    "TLS SANs",
                    f"{len(san_list)} SANs: {', '.join(san_list[:5])}"
                    + (f" ... (+{len(san_list)-5} more)" if len(san_list) > 5 else ""),
                )

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------
    def scan(self):
        self._log(f"\n{'='*65}")
        self._log(f" Citrix NetScaler Version Detection")
        self._log(f" Target: {self.target}")
        self._log(f" Fingerprint DB: {len(VSTAMP_TO_VERSION)} timestamps,"
                   f" {len(VHASH_TO_VERSION)} MD5 hashes")
        self._log(f"{'='*65}\n")

        # --- Phase 1: GZIP Timestamp Fingerprinting (most reliable) ---
        self._log("[*] Phase 1: GZIP timestamp fingerprinting (rdx_en.json.gz)...")
        self.check_gzip_fingerprint()

        # --- Phase 2: Root URL and headers ---
        self._log("\n[*] Phase 2: Checking root URL, headers, and redirects...")
        root_resp = self._get("/")
        if root_resp is not None:
            self.check_headers(root_resp, "/")
            self.check_body_indicators(root_resp.text, "/")
            self.check_title_tag(root_resp.text, "/")
            self.check_body_versions(root_resp.text, "/")
            if root_resp.history:
                final_url = root_resp.url
                if any(p in final_url for p in ["/logon/", "/vpn/", "/cgi/"]):
                    self.is_citrix = True
                    self._add_finding("Redirect", f"Root redirects to {final_url}")

        # --- Phase 3: Probe known endpoints ---
        self._log("\n[*] Phase 3: Probing known Citrix endpoints...")
        for path, description in PROBE_ENDPOINTS.items():
            resp = self._get(path)
            if resp is None:
                continue
            status = resp.status_code
            self._log(f"  [{'+'if status == 200 else '-'}] {path} -> HTTP {status}")

            if status == 200:
                self.is_citrix = True
                self._add_finding(f"Endpoint ({path})", f"{description} -- HTTP 200")
                self.check_headers(resp, path)
                self.check_body_indicators(resp.text, path)
                self.check_body_versions(resp.text, path)
                self.check_title_tag(resp.text, path)
                if "index.html" in path:
                    self.check_index_vhash(resp.text, path)
                if "pluginlist.xml" in path:
                    self.check_pluginlist_epa(resp.text, path)
            elif status in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                if any(k in loc.lower() for k in ["citrix", "netscaler", "vpn", "logon"]):
                    self.is_citrix = True
                    self._add_finding(f"Redirect ({path})", f"-> {loc}")
            elif status == 403:
                self._add_finding(f"Endpoint ({path})",
                                  f"{description} -- HTTP 403 (exists but forbidden)")

        # --- Phase 4: Build-specific JS resources ---
        self._log("\n[*] Phase 4: Checking build-specific JS resources...")
        build_paths = [
            "/vpn/js/gateway_login_view.js",
            "/vpn/js/gateway_login_form_view.js",
            "/logon/LogonPoint/custom/script.js",
            "/logon/LogonPoint/receiver/js/ctxs.core.min.js",
            "/html/framework/js/core.min.js",
        ]
        for path in build_paths:
            resp = self._get(path)
            if resp is None or resp.status_code != 200:
                continue
            self._log(f"  [+] {path} -> HTTP 200")
            self.is_citrix = True
            self.check_body_versions(resp.text, path)

        # --- Phase 5: EPA binary PE version extraction ---
        self._log("\n[*] Phase 5: Checking EPA binary version metadata...")
        self.check_epa_binary()

        # --- Phase 6: Favicon fingerprinting ---
        self._log("\n[*] Phase 6: Favicon fingerprinting...")
        self.check_favicon()

        # --- Phase 7: Static file content hashing ---
        self._log("\n[*] Phase 7: Static file content hashing...")
        self.check_static_file_hashes()

        # --- Phase 8: TLS certificate analysis ---
        self._log("\n[*] Phase 8: TLS certificate analysis...")
        self.check_tls_cert()

        self._print_results()

    # ------------------------------------------------------------------
    # CVE Assessment
    # ------------------------------------------------------------------
    def _assess_cves(self, version_str: str) -> list[dict]:
        vt = parse_version(version_str)
        if not vt:
            return []

        results = []
        for cve_id, (desc, check_fn) in CVE_CHECKS.items():
            vulnerable = check_fn(vt)
            results.append({
                "cve": cve_id,
                "description": desc,
                "vulnerable": vulnerable,
            })
        return results

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    def _print_results(self):
        self._log(f"\n{'='*65}")
        self._log(" RESULTS")
        self._log(f"{'='*65}\n")

        if not self.is_citrix:
            self._log("[!] No Citrix product detected on this target.\n")
            return

        # Determine best version (prefer GZIP fingerprint)
        best_version = self.gzip_version

        # If no GZIP match, look for NetScaler firmware versions in findings.
        # NetScaler firmware versions contain a dash: "14.1-56.74", "13.1-48.47"
        # Plugin/component versions use only dots: "25.5.1.15", "4.3.4619.0"
        if not best_version:
            firmware_versions = [
                v for v in self.versions_found
                if "-" in v and parse_version(v) is not None
                and parse_version(v).major in range(11, 15)
            ]
            if firmware_versions:
                best_version = sorted(firmware_versions, key=lambda v: parse_version(v))[-1]

        # --- Detailed findings first (verbose, scrolls off screen) ---
        self._log(f"  Total findings: {len(self.findings)}\n")
        self._log("  Detailed findings:")
        self._log(f"  {'-'*55}")
        for f in self.findings:
            ver = f" [v{f['version']}]" if f["version"] else ""
            self._log(f"  {f['source']}: {f['detail']}{ver}")

        # --- Summary at the bottom (always visible) ---
        self._log(f"\n{'='*65}")
        self._log(" SUMMARY")
        self._log(f"{'='*65}\n")

        self._log(f"  Target: {self.target}")
        self._log(f"  [+] Citrix NetScaler DETECTED\n")

        if best_version:
            vt = parse_version(best_version)
            fips_tag = ""
            if vt:
                if is_fips_13_1(vt):
                    fips_tag = " (FIPS/NDcPP build)"
                elif is_fips_12_1(vt):
                    fips_tag = " (FIPS/NDcPP build)"
                eol_tag = " [EOL]" if is_eol(vt) else ""
            else:
                eol_tag = ""

            self._log(f"  Best version match: {best_version}{fips_tag}{eol_tag}")
            if self.gzip_version:
                self._log(f"  Confidence: HIGH (GZIP timestamp fingerprint)")
            else:
                self._log(f"  Confidence: MEDIUM (pattern/header match)")

        if self.gzip_stamp and not self.gzip_version:
            # GZIP file was found but timestamp not in database
            # Find the nearest known version for context
            nearest = None
            min_diff = float("inf")
            for stamp_k, ver_k in VSTAMP_TO_VERSION.items():
                if ver_k == "unknown":
                    continue
                diff = self.gzip_stamp - stamp_k
                if 0 < diff < min_diff:
                    min_diff = diff
                    nearest = ver_k
            self._log(f"  Firmware build date: {self.gzip_date}")
            self._log(f"  GZIP timestamp: {self.gzip_stamp} (not in fingerprint DB)")
            if nearest:
                days = min_diff / 86400
                self._log(f"  Nearest older known version: {nearest}"
                           f" ({days:.0f} days older)")
                self._log(f"  Likely version: newer than {nearest}")
            self._log(f"  Confidence: MEDIUM (timestamp extrapolation)")

        if not best_version and not self.gzip_stamp and not self.versions_found:
            self._log("  [!] Citrix presence confirmed but exact version could not")
            self._log("      be determined from available endpoints.")

        # Show component versions found (filtered for readability)
        if self.versions_found:
            firmware_vs = [v for v in self.versions_found if parse_version(v) is not None]
            component_vs = [v for v in self.versions_found if parse_version(v) is None]
            if firmware_vs:
                self._log(f"\n  Firmware/component version(s):")
                for v in sorted(firmware_vs):
                    marker = " <-- best" if v == best_version else ""
                    self._log(f"    - {v}{marker}")
            if component_vs:
                self._log(f"\n  Other version strings (plugins/JS libs):")
                for v in sorted(component_vs):
                    self._log(f"    - {v}")

        # CVE assessment — use best_version, or extrapolated nearest version
        cve_version = best_version
        if not cve_version and self.gzip_stamp and not self.gzip_version:
            # Use the nearest older known version for CVE assessment
            nearest_ver = None
            min_diff = float("inf")
            for stamp_k, ver_k in VSTAMP_TO_VERSION.items():
                if ver_k == "unknown":
                    continue
                diff = self.gzip_stamp - stamp_k
                if 0 < diff < min_diff:
                    min_diff = diff
                    nearest_ver = ver_k
            if nearest_ver:
                cve_version = nearest_ver

        if self.check_cves and cve_version:
            label = cve_version
            if cve_version != best_version and self.gzip_stamp:
                label = f">= {cve_version} (extrapolated from build date {self.gzip_date})"
            self._log(f"\n  {'~'*55}")
            self._log(f"  CVE VULNERABILITY ASSESSMENT (version {label})")
            self._log(f"  {'~'*55}")

            cve_results = self._assess_cves(cve_version)
            if not cve_results:
                self._log("  [!] Could not parse version for CVE checks.")
            else:
                vuln_count = sum(1 for r in cve_results if r["vulnerable"])
                for r in cve_results:
                    status = "VULNERABLE" if r["vulnerable"] else "Not affected"
                    icon = "!!" if r["vulnerable"] else "ok"
                    self._log(f"  [{icon}] {r['cve']}: {status}")
                    self._log(f"       {r['description']}")

                if vuln_count > 0:
                    self._log(f"\n  >> {vuln_count}/{len(cve_results)} CVEs affect"
                              f" this version. Patching recommended.")
                else:
                    self._log(f"\n  >> No known CVEs affect this version.")

        self._log(f"\n{'='*65}\n")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Detect Citrix NetScaler ADC/Gateway version via GZIP timestamp "
            "fingerprinting, header analysis, and endpoint probing."
        ),
        epilog="For authorized security assessments only.",
    )
    parser.add_argument("target", help="Target URL (e.g. https://vpn.example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("-a", "--user-agent", default=None,
                        help="Custom User-Agent string")
    parser.add_argument("--cve", action="store_true",
                        help="Run CVE vulnerability assessment against detected version")
    args = parser.parse_args()

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    detector = CitrixDetector(target, timeout=args.timeout, user_agent=args.user_agent,
                              check_cves=args.cve)
    detector.scan()

    sys.exit(0 if detector.is_citrix else 1)


if __name__ == "__main__":
    main()
