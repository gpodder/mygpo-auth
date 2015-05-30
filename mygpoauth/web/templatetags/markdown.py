import markdown as md
import bleach

from django import template
from django.utils.html import conditional_escape
from django.utils.safestring import mark_safe
from django.template.defaultfilters import stringfilter


register = template.Library()

ALLOWED_TAGS = bleach.ALLOWED_TAGS + ['p']


@register.filter
@stringfilter
def markdown(value):
    s = mark_safe(bleach.clean(md.markdown(value), tags=ALLOWED_TAGS))
    return s
