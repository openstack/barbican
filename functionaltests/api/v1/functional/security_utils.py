# Copyright (c) 2015 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import re
import base64
import urllib
import json


class Fuzzer():
    def __init__(self, default_fuzz_type='all', default_encoding_type='none'):
        self.types = [
            'all', 'sql', 'xss', 'xml', 'json', 'ascii', 'unicode',
            'content_types', 'date', 'huge', 'junk', 'json_recursion',
            'date', 'bad_numbers'
        ]

        self.named_types = [
            'content_types', 'date', 'huge', 'junk', 'xss', 'quick',
            'bad_numbers'
        ]

        self.encoding_types = [
            'none', 'b64encode', 'b64decode', 'urlencode', 'urlencode'
        ]

        self.fuzz_file_dir = '/Users/char7232/wordlists'

        self.default_fuzz_type = default_fuzz_type
        self.default_encoding_type = default_encoding_type

        # Define some barbican-specific fuzz strings w/ short names
        self.content_types = {
            'atom_xml': 'application/atom+xml',
            'app_xml': 'application/xml',
            'txt_xml': 'text/xml',
            'app_soap_xml': 'application/soap+xml',
            'app_rdf_xml': 'application/rdf+xml',
            'app_rss_xml': 'application/rss+xml',
            'app_js': 'application/javascript',
            'app_ecma': 'application/ecmascript',
            'app_x_js': 'application/x-javascript',
            'txt_js': 'text/javascript',
            'app_pkcs12': 'application/x-pkcs12',
            'app_form': 'application/x-www-form-urlencoded',
            'multipart_enc': 'multipart/encrypted',
            'multipart_form': 'multipart/form-data',
            'msg_http': 'message/http',
            'msg_partial': 'message/partial',
            'junk': 'junk',
            'app_json_w_null': 'application/json' + chr(0x00),
            'octet_stream_w_null': 'application/octet-stream' + chr(0x00),
            'text_plain_w_null': 'text/plain' + chr(0x00),
            'app_json_w_0xff': 'application/json' + unichr(0xff),
            'octet_stream_w_0xff': 'application/octet-stream' + unichr(0xff),
            'text_plain_w_0xff': 'text/plain' + unichr(0xff)
        }

        self.date = {
            'date_w_null': '2018-02-28T19:14:44.180394' + chr(0x00),
            'date_w_unicode': '2018-02-28T19:14:44.180394' + unichr(0xff),
            'date_w_format': '2018-02-28T19:%f14:44.180394',
            'huge': '2018-02-28T12:12:12.' + ('4' * 100000),
        }

        self.huge = {
            '10^3': 'a' * 10 ** 3,
            '10^4': 'a' * 10 ** 4,
            '10^5': 'a' * 10 ** 5,
            '10^6': 'a' * 10 ** 6,
            '10^7': 'a' * 10 ** 7
        }

        self.xss = {
            'double_bracket': '<<script>alert(1);//<</script>',
            'tag_close': '\'"><script>alert(1);</script>',
            'img_js_link': '<IMG SRC=javascript:alert(1)>',
            'img_js_link_w_0x0D': '<IMG SRC=jav&#x0D;ascript:alert(1);>',
            'img_js_link_overencode':
                "<IMG%20SRC='%26%23x6a;avasc%26%23000010ript:a%26%23x6c;ert"
                "(1)'>",
            'iframe_js_link': '<IFRAME SRC=javascript:alert(1)></IFRAME>',
            'js_context': '\\";alert(1);//'
        }

        self.sqli = {
            'hex_select': '\\x27\\x4F\\x52 SELECT *',
            'hex_union': '\\x27UNION SELECT',
            'or_select': '\'"or select *',
            'or_x_is_x': '\' or \'x\'=\'x',
            '0_or_1_is_1': '0 or 1=1',
            '0_or_1_is_1_dashed': '0 or 1=1 --',
            'a_or_x_is_x_dquote': 'a" or "x"="x',
            'a_or_x_is_x_squote': 'a\' or \'x\'=\'x',
            'a_or_x_is_x_paren_dqoute': 'a") or ("x"="x',
            'a_or_x_is_x_paren_sqoute': 'a\') or (\'x\'=\'x',
            'a_or_x_is_x_full_statement': '\'a\' or \'x\'=\'x\';'
        }

        self.xml = {
            'xml_xxe_etc_passwd':
                '<?xml version="1.0" encoding="ISO-8859-1"?>'
                '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM'
                ' "file:////etc/passwd">]><foo>&xxe;</foo>',
            'xml_sqli':
                '<?xml version="1.0" encoding="ISO-8859-1"?><foo>'
                '<![CDATA[\'or 1=1 or \'\'=\']]></foo>'
        }

        self.junk = {
            'nullbyte': chr(0x00),
            'higher_ascii': chr(0x80) + chr(0xfe),
            'higher_unicode': unichr(0x1111) + unichr(0xffff),
            'unicode_single_quote': unichr(0x2018),
            'unicode_double_quote': unichr(0x201c),
            'huge': 'a' * 100000
        }

        self.bad_numbers = {
            'negative_zero': '-0',
            'negative_hex': '-0xff',
            'overflow': 999999999999999,
            'negative_overflow': -999999999999999,
            'negative_float_overflow': -0.999999999999999,
            'hex_overflow': '0xffffffff',
            'extreme_overflow': 9 ** 100,
            'nullbyte': chr(0x00)
        }

        self.rce = {
            'semicolon_id': ';id',
            'or_id': '||id',
            'and_id': '&&id',
            'nullbyte_id': chr(0) + 'id',
            'urlencoded_nullbyte_id': '%00id',
            'newline_id': chr(0x0a) + 'id',
            'urlencoded_nullbyte_id': '%0aid',
            'backticks_id': '`id`',
            'close_parens_id': ');id'
        }

    def encode_string(self, string, encoding=None):
        """Encode a single string with the given encoding type"""
        if encoding not in self.encoding_types or encoding is None:
            encoding = self.default_encoding_type

        if encoding == 'none':
            return string
        elif encoding == 'b64encode':
            return base64.b64encode(string)
        elif encoding == 'b64decode':
            return base64.b64decode(string)
        elif encoding == 'urlencode':
            return urllib.quote(string)
        elif encoding == 'urldecode':
            return urllib.unquote(string)

    def encode_strings(self, strings, encoding=None):
        """Encode a list or dict of strings with the given encoding type"""
        result = None

        if encoding not in self.encoding_types:
            print 'Unknown encoding type'
            return False
        if not isinstance(strings, list) and not isinstance(strings, dict):
            print 'Unknown format for strings'
            return False

        if isinstance(strings, list):
            result = []
            for string in strings:
                result.append(self.encode_string(string))
            return result

        elif isinstance(strings, dict):
            result = {}
            for name in strings:
                result[name] = self.encode_string(strings[name])
            return result

    def get_strings(self, fuzz_string_type=None, encoding=None):
        """Get a set of fuzz strings, either by generating them or reading them
        from a file

        Valid types defined in self.types
        """

        fuzz_file = None
        fuzz_strings = []

        if fuzz_string_type not in self.types or fuzz_string_type is None:
            fuzz_string_type = self.default_fuzz_type

        # Load fuzz strings from a file
        if fuzz_string_type == "sql":
            fuzz_file = os.path.join(self.fuzz_file_dir, "sql.txt")

        # elif fuzz_string_type == "xss":
        #    fuzz_file = os.path.join(self.fuzz_file_dir, "xss.txt")

        elif fuzz_string_type == "xml":
            fuzz_file = os.path.join(self.fuzz_file_dir, "xml.txt")

        elif fuzz_string_type == "json":
            fuzz_file = os.path.join(self.fuzz_file_dir, "json.txt")

        # elif fuzz_string_type == "content_types":
        #    fuzz_file = os.path.join(self.fuzz_file_dir, "content_types.txt")

        elif fuzz_string_type == "all":
            fuzz_file = os.path.join(self.fuzz_file_dir, "all.txt")

        if fuzz_file:
            with open(fuzz_file, "r") as f:
                contents = f.read()
                for line in contents.split("\n"):
                    if line.strip():
                        fuzz_strings.append(line.strip())

        # Generate fuzz strings on the fly
        elif fuzz_string_type == "ascii":
            for i in xrange(0, 256):
                fuzz_strings.append(chr(i))

        elif fuzz_string_type == "unicode":
            for i in xrange(0, 0x1000):
                fuzz_strings.append(unichr(i))
            for i in xrange(0xf800, 0x10000):  # Random
                fuzz_strings.append(unichr(i))

        elif fuzz_string_type == "content_types":
            for name in self.content_types:
                fuzz_strings.append(self.content_types[name])

        elif fuzz_string_type == "xss":
            for name in self.xss:
                fuzz_strings.append(self.xss[name])

        elif fuzz_string_type == "json_recursion":
            obj = {}
            string = 'obj["hax"]'
            for i in xrange(850):
                exec(string + ' = {}')
                string += '["hax"]'
            fuzz_strings.append(json.dumps(obj))

        elif fuzz_string_type in self.named_types:
            temp = self.__dict__[fuzz_string_type]
            for name in temp:
                fuzz_strings.append(temp[name])

        return fuzz_strings

    def get_dataset(self, fuzz_string_type):
        strings = self.get_strings(fuzz_string_type)
        result = {}

        for string in strings:
            name = self.get_fuzz_string_name(fuzz_string_type, string)
            result[name] = [string]
        return result

    # TODO(cneill)
    # Get rid of this in favor of loading name+string from a config file?
    def get_fuzz_string_name(self, fuzz_string_type, fuzz_string, num=False):
        result = None

        if fuzz_string_type in self.named_types:
            for name, string in self.__dict__[fuzz_string_type].iteritems():
                if string == fuzz_string:
                    result = name
                    break
        else:
            # Get first 20 characters, trim trailing spaces, convert
            # non-alphanumeric characters to underscores
            fuzz_string = re.sub(
                "[^a-z0-9A-Z]*", "_", fuzz_string[:20].strip()
            )
            result = "{0}_{1}".format(fuzz_string_type, fuzz_string)
            if num is not False and isinstance(num, int):
                result = "{0}_{1}".format(result, num)
        return result

    def fuzz_model(self, model_type, skeleton={}, fuzz_string_type="all",
                   fuzz_type="single"):
        """Take a model and a skeleton, and return a list of models with fuzz
        strings replacing parameters

        fuzz_type = ["single", "all"]"""

        temp = model_type()
        params = dir(temp)
        fuzz_strings = self.get_strings(fuzz_string_type)
        fuzzed_models = []

        for fuzz_string in fuzz_strings:
            overrides = {}
            for i, variable in enumerate(params):
                if fuzz_type == "single":
                    overrides = {}

                if (callable(getattr(temp, variable))
                        or variable.startswith("__")):
                    continue

                overrides[variable] = fuzz_string
                model = model_type(**skeleton)
                model.override_values(**overrides)

                if fuzz_type == "single":
                    fuzzed_models.append(model)

                elif fuzz_type == "all":
                    if i == len(params) - 1:
                        fuzzed_models.append(model)

        return fuzzed_models
