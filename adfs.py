import datetime
import string
import urllib2
import uuid

import requests
from lxml import etree


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
    def _uuid4(self):
        return str(uuid.uuid4())

    @staticmethod
    def _first(l):
        return l[0]

    def _prepare_adfs_request(self):

        """Build the ADFS Request Security Token SOAP message.

        Some values like username or password are inserted in the request.

        """
        NAMESPACES = {
            's': 'http://www.w3.org/2003/05/soap-envelope',
            'a': 'http://www.w3.org/2005/08/addressing',
            'u': ('http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                  'wss-wssecurity-utility-1.0.xsd')
        }

        WSS_SECURITY_NAMESPACE = {
            'o': ('http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                  'wss-wssecurity-secext-1.0.xsd')
        }

        TRUST_NAMESPACE = {
            'trust': 'http://docs.oasis-open.org/ws-sx/ws-trust/200512'
        }

        WSP_NAMESPACE = {
            'wsp': 'http://schemas.xmlsoap.org/ws/2004/09/policy'
        }

        WSA_NAMESPACE = {
            'wsa': 'http://www.w3.org/2005/08/addressing'
        }

        root = etree.Element(
            '{http://www.w3.org/2003/05/soap-envelope}Envelope',
            nsmap=NAMESPACES)

        header = etree.SubElement(
            root, '{http://www.w3.org/2003/05/soap-envelope}Header')
        action = etree.SubElement(
            header, "{http://www.w3.org/2005/08/addressing}Action")
        action.set(
            "{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", "1")
        action.text = ('http://docs.oasis-open.org/ws-sx/ws-trust/200512'
                       '/RST/Issue')

        messageID = etree.SubElement(
            header, '{http://www.w3.org/2005/08/addressing}MessageID')
        messageID.text = 'urn:uuid:' + self._uuid4
        replyID = etree.SubElement(
            header, '{http://www.w3.org/2005/08/addressing}ReplyTo')
        address = etree.SubElement(
            replyID, '{http://www.w3.org/2005/08/addressing}Address')
        address.text = 'http://www.w3.org/2005/08/addressing/anonymous'

        to = etree.SubElement(
            header, '{http://www.w3.org/2005/08/addressing}To')
        to.set("{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", "1")
        to.text = self.adfs_url

        security = etree.SubElement(
            header, '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
            'wss-wssecurity-secext-1.0.xsd}Security',
            nsmap=WSS_SECURITY_NAMESPACE)

        security.set(
            "{http://www.w3.org/2003/05/soap-envelope}mustUnderstand", "1")

        timestamp = etree.SubElement(
            security, ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                       'wss-wssecurity-utility-1.0.xsd}Timestamp'))
        timestamp.set(
            ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
             'wss-wssecurity-utility-1.0.xsd}Id'), '_0')

        created = etree.SubElement(
            timestamp, ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                        'wss-wssecurity-utility-1.0.xsd}Created'))

        expires = etree.SubElement(
            timestamp, ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                        'wss-wssecurity-utility-1.0.xsd}Expires'))

        created.text, expires.text = self._token_dates()

        usernametoken = etree.SubElement(
            security, '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-'
                      'wss-wssecurity-secext-1.0.xsd}UsernameToken')
        usernametoken.set(
            ('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-'
             'wssecurity-utility-1.0.xsd}u'), "uuid-%s-1" % self._uuid4)

        username = etree.SubElement(
            usernametoken, ('{http://docs.oasis-open.org/wss/2004/01/oasis-'
                            '200401-wss-wssecurity-secext-1.0.xsd}Username'))
        username.text = self.username
        password = etree.SubElement(
            usernametoken, ('{http://docs.oasis-open.org/wss/2004/01/oasis-'
                            '200401-wss-wssecurity-secext-1.0.xsd}Password'),
            Type=('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-'
                  'username-token-profile-1.0#PasswordText'))

        password.text = self.password

        body = etree.SubElement(
            root, "{http://www.w3.org/2003/05/soap-envelope}Body")

        request_security_token = etree.SubElement(
            body, ('{http://docs.oasis-open.org/ws-sx/ws-trust/200512}'
                   'RequestSecurityToken'), nsmap=TRUST_NAMESPACE)

        applies_to = etree.SubElement(
            request_security_token,
            '{http://schemas.xmlsoap.org/ws/2004/09/policy}AppliesTo',
            nsmap=WSP_NAMESPACE)

        endpoint_reference = etree.SubElement(
            applies_to,
            '{http://www.w3.org/2005/08/addressing}EndpointReference',
            nsmap=WSA_NAMESPACE)

        wsa_address = etree.SubElement(
            endpoint_reference,
            '{http://www.w3.org/2005/08/addressing}Address')
        wsa_address.text = self.sp_endpoint
        keytype = etree.SubElement(
            request_security_token,
            '{http://docs.oasis-open.org/ws-sx/ws-trust/200512}KeyType')
        keytype.text = ('http://docs.oasis-open.org/ws-sx/'
                        'ws-trust/200512/Bearer')

        request_type = etree.SubElement(
            request_security_token,
            '{http://docs.oasis-open.org/ws-sx/ws-trust/200512}RequestType')
        request_type.text = ('http://docs.oasis-open.org/ws-sx/'
                             'ws-trust/200512/Issue')
        token_type = etree.SubElement(
            request_security_token,
            '{http://docs.oasis-open.org/ws-sx/ws-trust/200512}TokenType')
        token_type.text = 'urn:oasis:names:tc:SAML:1.0:assertion'

        self.prepared_request = root

    @property
    def prepared_request_str(self):
        try:
            self._prepared_request_str
        except AttributeError:
            self._prepare_adfs_request()
            # noinspection PyAttributeOutsideInit
            self._prepared_request_str = etree.tostring(self.prepared_request)
        finally:
            return self._prepared_request_str

    def _get_adfs_security_token(self):
        adfs_response = self.session.post(
            url=self.adfs_url, headers=self.HEADER_SOAP,
            data=self.prepared_request_str, verify=self.verify)
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
        self.session.post(
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

    def access_resource(self, **kwargs):
        r = self.session.get(url=self.sp_url, verify=self.verify,
                             **kwargs)
        if r.ok:
            return r.content

