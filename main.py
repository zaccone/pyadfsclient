#!/usr/bin/env python

import argparse
import logging
import os

import adfs

def build_parser():
    parser =  argparse.ArgumentParser(description='ADFSClient')
    parser.add_argument('--adfs_url', help='URL of you ADFS server')
    parser.add_argument('--sp_endpoint', default=None,
                        help=('URL of your Service PRovider special endpoint,'
                              'e.g. https://host.example/Shibboleth.sso/ADFS'))
    parser.add_argument('--sp_url', default=None,
                        help='URL of the protected resource')
    parser.add_argument('--user', default=None,
                        help='Username for ADFS authentication.')
    parser.add_argument('--password', default=None,
                        help='Password for ADFS authentication.')
    parser.add_argument('--no-ssl', dest='verify',
                        action='store_false',
                        help=("Dont't verify SSL certificates "
                              "(defaults to False)"))
    parser.add_argument('--cookie', dest='cookie', action='store_true',
                        help=('Print cookie after authentication '
                              '(defaults to False)'))
    parser.add_argument('--content', dest='content',
                        action='store_true',
                        help=('Print protected content to the output '
                              '(defaults to False)'))
    return parser

def set_options(args):
    options = {}
    options['user'] = args.user or os.environ.get('ADFS_USER')
    options['password'] = args.password or os.environ.get('ADFS_PASSWORD')
    options['adfs_url'] = args.adfs_url or os.environ.get('ADFS_URL')
    options['sp_url'] = args.sp_url or os.environ.get('SP_URL')
    options['sp_endpoint'] = args.sp_endpoint or os.environ.get('SP_ENDPOINT')
    options['verify'] = os.environ.get('ADFS_VERIFY_SSL') or args.verify
    options['cookies'] = os.environ.get('ADFS_COOKIE') or \
                         args.cookie
    options['content'] = os.environ.get('ADFS_PRINT_CONTENT') or \
                         args.content

    return options

def main():
    parser = build_parser()
    args = parser.parse_args()
    options = set_options(args)
    client = adfs.ADFSClient(options['user'], options['password'],
                             options['adfs_url'], options['sp_endpoint'],
                             options['sp_url'], verify=options['verify'])
    client.login()
    if all([options['content'], options['sp_url']]):
        print client.access_resource()
    elif options['content']  and not options['sp_url']:
        print "Missing sp_url argument"

    if options['cookies']:
        print str(client.get_cookie())

if __name__ == '__main__':
    main()
