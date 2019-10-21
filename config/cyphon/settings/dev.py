"""
[`source`_]

Development Django settings for Cyphon.

For more information on this Django file, see:
https://docs.djangoproject.com/en/1.11/topics/settings/

For the full list of Django settings and their values, see:
https://docs.djangoproject.com/en/1.11/ref/settings/

.. _source: ../_modules/cyphon/settings/dev.html

"""

# local
from .base import *


#: URL for constructing link with MEDIA_URL.
BASE_URL = os.getenv('BASE_URL_DEV', 'http://localhost:8000')

#: Whether to enable debug mode.
DEBUG = True

#: A logging configuration dictionary.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(name)s '
                      '%(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'mail_admins': {
            'level': 'WARNING',
            'class': 'django.utils.log.AdminEmailHandler'
        },
    },
    'loggers': {
        'django.server': {
            'handlers': ['console'],
            'propagate': True,
            'level': 'DEBUG'
        },
        'django.request': {
            'handlers': ['console'],
            'propagate': True,
            'level': 'DEBUG'
        },
        'django': {
            'handlers': ['console'],
            'propagate': True,
            'level': 'INFO',
        },
        'receiver': {
            'handlers': ['console'],
            'propagate': True,
            'level': 'DEBUG',
        },
    }
}
