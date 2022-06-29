from __future__ import absolute_import, division, print_function, unicode_literals

import os
from socket import timeout
import sys

splunkhome = os.environ['SPLUNK_HOME']
sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'splunk_app_for_threatbook', 'lib'))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib import six

import json
import requests


@Configuration()
class TipCommand(StreamingCommand):
    key = Option(name='key', require=True)
    type = Option(name='type', require=True)
    field = Option(name='field', require=True)

    def stream(self, records):
        # ip
        if self.type == "ip":
            ip_url = "https://api.threatbook.cn/v3/scene/ip_reputation"
            for record in records:
                query = {"apikey": self.key, "resource": record[self.field]}
                try:
                    response = requests.request("GET", url=ip_url, params=query, timeout=5)
                    results = response.json()
                    self.logger.debug(results)
                    if results["response_code"] == 0:
                        for zz in results["data"]:
                            # is_malicious
                            if results["data"][zz]['is_malicious']:
                                record["is_malicious"] = "Yes"
                            else:
                                record["is_malicious"] = "No"
                            record["judgments"] = results["data"][zz]["judgments"]
                            record["response_code"] = results["response_code"]
                            record["verbose_msg"] = results["verbose_msg"]
                            record["carrier"] = results["data"][zz]["basic"]["carrier"]
                            record["city"] = results["data"][zz]["basic"]["location"]["city"]
                            record["country"] = results["data"][zz]["basic"]["location"]["country"]
                            record["country_code"] = results["data"][zz]["basic"]["location"]["country_code"]
                            record["lat"] = results["data"][zz]["basic"]["location"]["lat"]
                            record["lng"] = results["data"][zz]["basic"]["location"]["lng"]
                            record["province"] = results["data"][zz]["basic"]["location"]["province"]
                            record["severity"] = results["data"][zz]["severity"]
                            if results["data"][zz]["tags_classes"]:
                                record["tags"] = results["data"][zz]["tags_classes"]
                            else:
                                record["tags"] = "null"
                            record["update_time"] = results["data"][zz]["update_time"]
                            self.logger.debug(record)
                            yield record
                    else:
                        record["response_code"] = results["response_code"]
                        record["verbose_msg"] = results["verbose_msg"]
                        yield record
                except Exception as e:
                    record["response_code"] = "-1"
                    record["verbose_msg"] = "ERROR:访问<" + ip_url + "> url 超时!请检查网络.详细内容:" + str(e)
                    yield record
        #  collapse
        elif self.type == "collapse":
            collapse_url = "https://api.threatbook.cn/v3/scene/dns"
            for record in records:
                query = {"apikey": self.key, "resource": record[self.field]}
                self.logger.debug(query)
                try:
                    response = requests.request("GET", url=collapse_url, params=query, timeout=5)
                    results = response.json()
                    self.logger.debug(results)
                    if results["response_code"] == 0:
                        for zz in results["data"]:
                            for jj in results["data"][zz]:
                                # severity
                                if results["data"][zz][jj]["severity"]:
                                    record["severity"] = results["data"][zz][jj]["severity"]
                                else:
                                    record["severity"] = "null"
                                record["judgments"] = results["data"][zz][jj]["judgments"]
                                # tags_classes
                                if results["data"][zz][jj]["tags_classes"]:
                                    record["tag"] = results["data"][zz][jj]["tags_classes"]
                                else:
                                    record["tag"] = "null"
                                record["confidence_level"] = results["data"][zz][jj]["confidence_level"]
                                if results["data"][zz][jj]["is_malicious"]:
                                    record["is_malicious"] = "Yes"
                                else:
                                    record["is_malicious"] = "No"
                                
                                record["response_code"] = results["response_code"]
                                record["verbose_msg"] = results["verbose_msg"]
                                self.logger.debug(record)
                                yield record
                                
                    else:
                        record["response_code"] = results["response_code"]
                        record["verbose_msg"] = results["verbose_msg"]
                        yield record
                except Exception as e:
                        record["response_code"] = "-1"
                        record["verbose_msg"] = "ERROR:访问<" + collapse_url + "> url 超时!请检查网络.详细内容:" + str(e)
                        yield record

dispatch(TipCommand, sys.argv, sys.stdin, sys.stdout, __name__)
