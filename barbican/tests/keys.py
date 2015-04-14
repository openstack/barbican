# Copyright (c) 2015 Cisco Systems
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


def get_private_key_pkcs8():
    """Returns a private key in PCKS#8 format

    This key was created by issuing the following openssl commands:

    openssl genrsa -out private.pem 2048
    openssl pkcs8 -topk8 -nocrypt -in private.pem -out private.pk8

    The byte string returned by this function is the contents
    of the private.pk8 file.
    """

    return """-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCza2VoDXmBUMmw
jFu9F6MM5q/AZ1WjnWA2YNdNy237TrGN/nobDDv8FBBpUPmHNZ04H1LyxFcP8ReF
rcIXpifsReu2lAWaqRPxovu5CuAhfecKv+RhjLVLJ0I+MZIb72ROKpfZTmb7dhlF
gGD3vkC51BCfhGVW35w52OY/23x5MeO4yvx5myPccnxMVQ42KuDrzKqjBlSjmBnc
pGYx0JgCT+syFmHsl8rOkqCPPFLo24YQn+4/pr1AYwaZAbMTl9zoLtEQj6sxScuH
cS9e8niptDxlsbLQgqGVaGdE117stC95QH7UvITbuYzdjZwBFc1Sgz8GZ/2hLSsH
ujJiIQcvAgMBAAECggEAMOlUKbuSpigp85Ev6Sqqbnfs7Zy+Ae6DLg/UYgbVIq9f
RABdtUXujFfD6ZIDlFKPW59ec4QG3/evm+e0g9HuDEE7cviDVphFMZhm2xkV5Mt3
0rxhPB6pxaUcL+w/kpH+XDjMUJdJB8A4P3Qx+xfIeWBQb8wd/ELVSgfRLRNeqYL0
0KXVs04/FOBEhqSiqi/oHYJ4gxNrSoINX71PHVbaEikIygzi4HZVyMut3LE6ceHz
fSj71ftn+Ui0TzkLOb+NoBP31haHC/sfCrpKg7QtUP9q9dRq6dZcI17q5d7oEdET
eDRKhT2vm7bx2bLGeF1w2H9B/V81upjiAah2RVnecQKBgQDsfHSjR1gd+SHw/2A9
SaXS1k9LeXLt+UbDQdbjYOsh5LoT+EN/utO70RyDYqjlhzqJzciKTuAW5SVPC6gQ
uCppA29Kntq7x1+Lw/4wG947poXb60tLdg3BK5mBFTORk5ATqAwVq7t+2NtS5S/J
unzs5xrRolDFnSX4KnvVl6Jj3QKBgQDCOXZTVXRPEFhnqnqLErZe6EJkySwG8wgt
OdCmr660bocY1i9vV+RaM1iARHX6u/suMhkz+3KRinzxIG5gQsyiWmTpFV298W9v
kRtmsCQDn2my90yv4e6sLI0ng7l/N3r7CwLLNIV/CqeyaN40suzE8AjgEga5jTua
6bP5m+x8ewKBgQCeuW3DxXfkLjnUumMK36qX11XDb5FvHjebiE5FsOBAkHdAPgp3
6ZqBXfoISSjZXakxotft1MDdPRGMe2NjTWjRsQd6iyJ+lHORqIusGJhRaxQ/Ji8U
R/k1ZSETnXpORD+YodrylKA0pDKY8dDgUfXVP8wlVg9mg3JfnYweMTdCVQKBgQCx
133iNmgmkTfxzGci+wJkitVohdA7mMOO7daBGnKlImOvuUd784XTlhpecNF6wi/w
D82GDKLOY3meLO0EVYYczxqBVqAccXtxM/RcJcMEUi6twcXFcuJhYvXpDbOHqlyA
jIeFW9U1C6OcOGvm40Lr3UKzMa5Yrtq6MW4ri7uSCwKBgQDfdqVjT4uXmGwOh1z4
Pzv6GCoc+6GobXg4DvvCUjP9MR+2+5sX0AY/f+aVCD05/Nj0RqpAwUc03zZU5ZtL
2uNe6XDjEugfFtlzea6+rbD6KpFS+nxPJA8YyWYRpNhpRWGWQakHedr3BtMtGs0h
pKNAQG72HKWtSfJQMXvn2RlicA==
-----END PRIVATE KEY-----"""


def get_public_key_pem():
    """Returns a public key in PEM format

    This key was created by issuing the following openssl commands:

    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -pubout > public.pem

    The byte string returned by this function is the contents
    of the public.pem file.
    """

    return """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs2tlaA15gVDJsIxbvRej
DOavwGdVo51gNmDXTctt+06xjf56Gww7/BQQaVD5hzWdOB9S8sRXD/EXha3CF6Yn
7EXrtpQFmqkT8aL7uQrgIX3nCr/kYYy1SydCPjGSG+9kTiqX2U5m+3YZRYBg975A
udQQn4RlVt+cOdjmP9t8eTHjuMr8eZsj3HJ8TFUONirg68yqowZUo5gZ3KRmMdCY
Ak/rMhZh7JfKzpKgjzxS6NuGEJ/uP6a9QGMGmQGzE5fc6C7REI+rMUnLh3EvXvJ4
qbQ8ZbGy0IKhlWhnRNde7LQveUB+1LyE27mM3Y2cARXNUoM/Bmf9oS0rB7oyYiEH
LwIDAQAB
-----END PUBLIC KEY-----"""


def get_encrypted_private_key_pkcs8():
    """Returns an encrypted private key in PKCS#8 format

    This key was created by issuing the following openssl commands:

    openssl genrsa -out private.pem 2048
    echo password > passphrase.txt
    openssl pkcs8 -topk8 -passout file:passphrase.txt \
                  -in private.pem -out private_encrypted.pk8

    The byte string returned by this function is the contents
    of the private_encrypted.pk8 file.
    """

    return """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIE6TAbBgkqhkiG9w0BBQMwDgQIssadeQrYhhACAggABIIEyDNw3SV2b19yy4Q/
kTbtJ/p2X2zKDqr7GgLeAowqqhcMfvprI7G8C0XtwxkR4SjMZUXNcmOwQB2kNKtK
ZilCz6pSx81iUj4s1fU460XkhkIeV+F7aB2PsTG1oDfPCuzKFjT6EuSE6lFUH89r
TRuHWMPseW7lrvEB5kNMFag5QxeKjsSCNkZWOT74o4fh3cEplgCEaA+nCclXU79m
5rhaa9e1SUpPuPlhnAIDkBtHcC38B+SOYKQxLdZT1f72oZ1ozWJ4bEhKxvnNu5J+
tCvgWOXMIEJVGgf8Cu58PoR18LyyAIk7zza+1LkCiyuLNgiz8a1sVw8uBcrVgD5R
8f4XgI/Yjb16Bmpp/0iEjNcURaby9GnCCEc+W/ivSJTnG3o1Xn00FO98l2aggNpt
S8gxK05NeCtdWoFFjTeIXxnb1ct0Iep8RwuO+FnupAf6aw12Uqj4qYNvNiY/kBhS
P/Yd3KznasrolUZ9+PVTMUI45UTMN/XhNvXrozMq9nItWTV7wHyEL3mrYipvcxrm
SnLlAp2zkmSu923cHN1teLE99/rV2jaBM03ROqvYWaxjfOjxfwz6PhdE8G//kWd0
tf2Om+fyCkBRxo1sUcuiE79hJXgP5KJCMbPsDyG/aQk4oeS1nbn15AhthwiU7A13
h9X6asgV2H+4Ljf+tr1b8p3qj3CSljfzoVErLqoHagjVB45WktHhrWbUSRpXSvPo
Hh0LY62qxTa67gKjwarH5hYr5IaH39iR9bcyuvzE+u9TJWvWmeLJ7UmesfVPZtSf
/JTpvr0zu4C95lXKt4FdxOhGcWwDN1Zp+lCsF5ruBGc+/pEggiXi1qvW9xUny1Of
8NqdPxGPb4/zPHGaysypPsc6LiY3esI8wa7FnDsS4e79dWinD/BPWEa5N2jLm0Rr
njkHTy0xtnw/a8Ofrtyy9V1tBBOCaswzGIZZj6oHyFCtAvjZuYa8TWVmSi6EqJKi
lY5wSdQQXg3H0HnQYivtOY1YbfjtRkUB9e4xkSVhvYJpY1QWBtApdUGBsxsELkDC
6cv/Kxnd9U7dz9+VhD0hAdrhFqbWqOEGTWt7xE44yzWokdKQWu5FsTs6gyXsGPen
ZgZlR5pjPNGbMdftW0M473YyvtzjrCuSVgJspCzpA9uo6wfejaFb4RF/tcWtXglE
Q5FzfsO1OZr6nONraShj9N1kxGBXUUOtAjZI/zoTWk3yndxw3IpvPtDTg9ByCp7F
RFUtDyrki+YAIAiTgPq7qwc1upjU7R1Zlg4jIe0RI9A73NyLwa4QhgO+HmRBt7At
LLuUeCFKuXMBHzlDaMYwq5ZPOb8VcMkhUoug2YJIc4YOOHh5O0mYnat0vaYO+A58
DiuYgxKmO5+6+OMk2ovZgk1sFawR4rk9HUt8goUUptZ+hoHUVGtte5YcQniIOcds
qY3ni/zwswHWQRaAu8Ej4qJKt1XwZo2K04xHhL90TMaY8NpLSMCfVqDDL409TqIj
zHUfYl6N2Me4eKc8vl6Sm63g57NzLqTttD6KSn8v+OmUF5mOQwcLnr3nK7S+BQfI
DLPY1Oh7Kec/M/d1080/Qv9YBAJhz50TLKoxXwVeH4OOvuaHVaotElMkr5QEkEXl
gRgwkbMrQjg0II0O9g==
-----END ENCRYPTED PRIVATE KEY-----"""


def get_passphrase_txt():
    """Returns the plain text string used to encrypt the private key

    This key was created by issuing the following commands:

    echo password > passphrase.txt

    The byte string returned by this function is the contents
    of the passphrase.txt file.
    """

    return """password"""


def get_csr_pem():
    """Returns a Certificate Signing Request (CSR) in PEM format

    This key was created by issuing the following openssl commands:

    openssl genrsa -out private.pem 2048
    openssl req -new -key private.pem -out csr.pem -subj '/CN=example.com'

    The byte string returned by this function is the contents
    of the csr.pem file.
    """

    return """-----BEGIN CERTIFICATE REQUEST-----
MIICWzCCAUMCAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCza2VoDXmBUMmwjFu9F6MM5q/AZ1WjnWA2YNdN
y237TrGN/nobDDv8FBBpUPmHNZ04H1LyxFcP8ReFrcIXpifsReu2lAWaqRPxovu5
CuAhfecKv+RhjLVLJ0I+MZIb72ROKpfZTmb7dhlFgGD3vkC51BCfhGVW35w52OY/
23x5MeO4yvx5myPccnxMVQ42KuDrzKqjBlSjmBncpGYx0JgCT+syFmHsl8rOkqCP
PFLo24YQn+4/pr1AYwaZAbMTl9zoLtEQj6sxScuHcS9e8niptDxlsbLQgqGVaGdE
117stC95QH7UvITbuYzdjZwBFc1Sgz8GZ/2hLSsHujJiIQcvAgMBAAGgADANBgkq
hkiG9w0BAQsFAAOCAQEAPJDIxzgtUDRgpfTbTOPDJYap+Lm4jYxsCuAFbYiQ43B+
c7RyzEFOB2anrldTm3XzNytHZAkRTnN4dH09p1K1Pyepv+weSv8rvN9OohfYgpcj
wQqw8ksdGb3Q6oPnTgGxmWvV4PbzHmDnOvOiQ+wuBHWXYks6tdgU7iCZ1djYibmL
1j+XEvtstou8gu1lWhzH6tStwmA9udncg5rEvfDUDyvMN3T06QFqrlK9K1TXIlbM
RvUDrBjINIOuEeZ/5czjBl1CX1Z1YqdunrPiCQM4+oUAtjyD6ZAsyAEXLKdSYtKZ
hSZgIl7v+UAIM+9bhpVg15aTjRzfH2OsZodFIbsMDw==
-----END CERTIFICATE REQUEST-----"""


def get_certificate_pem():
    """Returns an X509 certificate in PEM format

    This key was created by issuing the following openssl commands:

    openssl genrsa -out private.pem 2048
    openssl req -new -x509 -key private.pem -out cert.pem \
                -days 1000 -subj '/CN=example.com'

    The byte string returned by this function is the contents
    of the cert.pem file.
    """

    return """-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIJAOLqXKJ9q9/nMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV
BAMMC2V4YW1wbGUuY29tMB4XDTE1MDQxMTAyMTUyOVoXDTE4MDEwNTAyMTUyOVow
FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQCza2VoDXmBUMmwjFu9F6MM5q/AZ1WjnWA2YNdNy237TrGN/nobDDv8
FBBpUPmHNZ04H1LyxFcP8ReFrcIXpifsReu2lAWaqRPxovu5CuAhfecKv+RhjLVL
J0I+MZIb72ROKpfZTmb7dhlFgGD3vkC51BCfhGVW35w52OY/23x5MeO4yvx5myPc
cnxMVQ42KuDrzKqjBlSjmBncpGYx0JgCT+syFmHsl8rOkqCPPFLo24YQn+4/pr1A
YwaZAbMTl9zoLtEQj6sxScuHcS9e8niptDxlsbLQgqGVaGdE117stC95QH7UvITb
uYzdjZwBFc1Sgz8GZ/2hLSsHujJiIQcvAgMBAAGjUDBOMB0GA1UdDgQWBBSUq2A0
b2Xo+sKvmKgN8Wq8l6j82jAfBgNVHSMEGDAWgBSUq2A0b2Xo+sKvmKgN8Wq8l6j8
2jAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBjiuqhlzNVOVLrHDQy
Gr0fTACFJdDREnuhZp4d91++DmMCT+bcTG0+GCp3rfFOuEWpJLLLPdSOnIsnibsO
syKPXuBBX5kmdYIojbdjUTSwnhcx9JTAfKSmxXWSC0rnKCefAf44Mm6fqvoTyTbe
GSQP6nHzc7eLaK/efcrMvYdct+TeTkHjqR8Lu4pjZvRdUQadQHhDyN+ONKdKD9Tr
jvfPim0b7Aq885PjSN6Qo4Z9HXR6+nK+bTz9HyUATMfDGNQt0L3vyfVxbNOxkCBc
YI4hFtGfkOzd6B7r2sY1wGKdTLHkuT4m4/9A/SOzvnH+epnJqIS9jw+1iRj8xcDA
6PNT
-----END CERTIFICATE-----"""
