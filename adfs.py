import copy
import datetime
import string
import urllib2
import uuid
import sys


import requests
from lxml import etree

import template

class ADFSClient(object):
    HEADER_SOAP = {"Content-Type": "application/soap+xml; charset=utf-8"}
    HEADER_X_FORM = {"Content-Type": "application/x-www-form-urlencoded"}
    ASSERTION_NAMESPACES = {
        's': 'http://www.w3.org/2003/05/soap-envelope',
        't': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512'
    }
    ADFS_ASSERTION_XPATH = ('/s:Envelope/s:Body'
                            '/t:RequestSecurityTokenResponseCollection'
                            '/t:RequestSecurityTokenResponse')

    def __init__(self,
                 username, password,
                 adfs_url,
                 sp_endpoint,
                 sp_url,
                 valid=3600,
                 verify=True):
        self.username = username
        self.password = password
        self.adfs_url = adfs_url
        self.sp_endpoint = sp_endpoint
        self.sp_url = sp_url
        self.valid = valid
        self.verify = verify

        self.session = requests.Session()

    def _token_dates(self, fmt='%Y-%m-%dT%H:%M:%S.%fZ'):
        date_created = datetime.datetime.utcnow()
        date_expires = date_created + datetime.timedelta(
            seconds=self.valid)
        return [_time.strftime(fmt) for _time in (date_created, date_expires)]

    @property
    def _uuid(self):
        return str(uuid.uuid4())

    def _first(self, l):
        return l[0]


    def _build_params_dict(self):
        date_created, date_expires = self._token_dates()
        PARAMS = {
            'MESSAGE_UUID': self._uuid,
            'USER_UUID': self._uuid,
            'DATE_CREATED': date_created,
            'DATE_EXPIRES': date_expires,
            'USERNAME': self.username,
            'PASSWORD': self.password,
            'SERVICE_PROVIDER_ENDPOINT': self.sp_endpoint,
            'ADFS_URL': self.adfs_url
        }
        return PARAMS

    def _prepare_adfs_request(self):
        request =  copy.deepcopy(template.TEMPLATE)
        self.prepared_request = request % self._build_params_dict()

    def _get_adfs_security_token(self):
        adfs_response = self.session.post(
            url=self.adfs_url, headers=self.HEADER_SOAP,
            data=self.prepared_request, verify=self.verify)
        # TODO(marek): check response
        self.adfs_token = adfs_response.content

    def _prepare_sp_request(self):
        tree = etree.XML(self.adfs_token)
        assertion = tree.xpath(self.ADFS_ASSERTION_XPATH,
                               namespaces=self.ASSERTION_NAMESPACES)
        assertion = self._first(assertion)
        assertion = etree.tostring(assertion)

        # FIXME(marek): Dirty hack. I should not replace serialized XML object
        # Unfortunately lxml doesn't allow for namespaces changing in-place
        # and probably the only solution for now is to build the assertion
        # from scratch and reuse values from the adfs security token.
        assertion = string.replace(
            assertion, 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
            'http://schemas.xmlsoap.org/ws/2005/02/trust')

        encoded_assertion = urllib2.quote(assertion.encode('utf8'))
        self.encoded_assertion = 'wa=wsignin1.0&wresult=' + encoded_assertion

    def _login_with_sp(self):
        response = self.session.post(
            url=self.sp_endpoint, data=self.encoded_assertion,
            headers=self.HEADER_X_FORM, allow_redirects=False,
            verify=self.verify)
        # TODO(marek): check response code

    def login(self):
        self._prepare_adfs_request()
        self._get_adfs_security_token()
        self._prepare_sp_request()
        self._login_with_sp()

    def get_session(self):
        return self.session

    def get_cookie(self):
        return self.session.cookies

    def access_resource(self, *args, **kwargs):
        r = self.session.get(url=self.sp_url, verify=self.verify,
                                *args, **kwargs)
        if r.ok:
            return r.content

