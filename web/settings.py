HOSTNAME       = 'localhost'
PORT           = 25800
GROUP_SIZE     = 1000
SOCKET_TIMEOUT = 40

MINIMAL_ASYNC_ITEMS = 5000

REDIS_URL   = "redis://localhost:6379/0"

RQ_QUEUE_NAME = 'hashtasks'

# Time to keep the results after the job is finished
# RQ default is 500 seconds
RQ_RESULT_TTL = '12h'

# Time to expend executing the job before trigger a timeout
# RQ default is 180 seconds
RQ_JOB_TIMEOUT = '20m'

# Time to keep failed jobs before being deleted
# RQ default is 1 year
RQ_FAILURE_TTL = '2d'
