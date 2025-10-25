
<div align="center">
  <img alt="d4-Plum-Island" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum_logo.png"   style="width:25%;" />

<h1> Proactive Land Uncovering & Monitoring </h1>
  <img alt="d4-Plum-Island" src="https://raw.githubusercontent.com/D4-project/Plum-Island/master/documentation/media/plum_overview.png" />
</div>
<p>
<center>
*Beta version*
</center>
</p>

## Description

This tool acts as an orchestrator for proactive surface-exposure discovery.
It assigns scanning tasks to agents, collects their results, and stores the data with full history. The collected information is queryable.

## Search capacity

The following keywords can be used to explore the data:

| Keyword | Modifier | Description |
| -------- | -------- | -------- |
| ip     |      | IP of the host  |
| net | | Cidr network, from /16 to /24 |
| fqdn | like, begin| fully qualified domain name|
| host | like, begin  | hostname, the subdomain part |
| domain | like, begin | dns domain |
| tld | like, begin | top level domain | 
| port | | Open port |
| http_title | like, begin | html title tag |
| http_cookiename | like, begin | Http set cookie keyname |
| http_etag | like, begin | http etag value |
| http_server | like, begin | http serveur value |
| x509_issuer | like, begin | 
| x509_md5 | | md5sum of the tls  certificate public signature   
| x509_sha1 | | sha1sum of the tls certificate public signature | 
| x509_sha256 | | sha256sum of the tls certificate public signature | 
| x509_subject |like, begin | tls certificate common name  |
| x509_san |like, begin |  tls certificate subject alternatives name |

modifier could be abreviated;  
* like to lk
* begin to bg

For now the query string only do AND between terms.

### Example of query

>domain.begin:"circl.lu" port:443 http_server.lk:nginx

Retrieve all Nginx http servers listening on port 443, with any mention to domain belonging to CIRCL.lu

## Technical requirements

- Python 3.10 
- Flask Appbuilder 4.8 (https://flask-appbuilder.readthedocs.io/en/latest/#) 
- meilisearch (https://www.meilisearch.com/) 
- Kvrocks (https://kvrocks.apache.org/) 

## Installation

Before starting the setup, please ensure that you have both a meilisearch and a kvrocks servers running and reachable.

To setup an environnement do;

```bash
git clone 
cd Plum-Island 
./setup.sh 
```
And review config.py for matching your configuration 

Then you could setup your prefered web server or simply run for demo
```bash
source ./venv/bin/activate  
cd webapp  
python run.sh  
```
