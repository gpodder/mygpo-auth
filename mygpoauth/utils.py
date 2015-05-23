

import collections


Link = collections.namedtuple('Link', 'target rel')


def get_link_header(links):
    """ Returns the value for a Link header (RFC 5988)

    https://tools.ietf.org/html/rfc5988 """
    return ', '.join(get_link(link) for link in links)


def get_link(link):
    """ Format one link for a HTTP Link header

    >>> get_link(Link('http://example.org/', \
                      ['start', 'http://example.net/relation/other']))
    '<http://example.org/>; rel="start http://example.net/relation/other"'

    >>> get_link(Link('http://example.org/', 'next'))
    '<http://example.org/>; rel="next"'
    """

    if isinstance(link.rel, list):
        rels = ' '.join(link.rel)
    else:
        rels = link.rel
    return '<{target}>; rel="{rels}"'.format(target=link.target, rels=rels)
