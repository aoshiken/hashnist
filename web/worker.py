#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import redis
import rq

# Propios...
import settings


###############################################################################

def start_worker( queue_name, redis_url, with_scheduler=False ):

    redis_conn = redis.from_url( redis_url )

    with rq.Connection( redis_conn ):

        worker = rq.Worker( queues     = [queue_name],
                            connection = redis_conn )

        worker.work( with_scheduler=with_scheduler )


###############################################################################
#
#
#
###############################################################################


if __name__ == '__main__':

    parser = argparse.ArgumentParser( formatter_class = argparse.RawTextHelpFormatter,
                                      description = 'Create Python RQ worker' )

    parser.add_argument( '-S', '--with-scheduler',
                         action = "store_true",
                         help   = 'Enable scheduler for worker' )

    parser.add_argument( '-u', '--redis-url',
                         default = settings.REDIS_URL,
                         type = str,
                         help = 'Redis URL (default: %s)' % settings.REDIS_URL)

    parser.add_argument( '-q', '--queue-name',
                         default = settings.RQ_QUEUE_NAME,
                         type    = str,
                         help    = 'Redis Queue name (default: %s)' %
                                                      settings.RQ_QUEUE_NAME)

    args = parser.parse_args()

    start_worker( queue_name     = args.queue_name,
                  redis_url      = args.redis_url,
                  with_scheduler = args.with_scheduler )
