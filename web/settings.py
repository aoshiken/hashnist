# Settings for MD5 hashchecker server:
MD5_HOSTNAME       = 'localhost'
MD5_PORT           = 25800
MD5_GROUP_SIZE     = 1000
MD5_SOCKET_TIMEOUT = 40

# Settings for SHA256 hashchecker server:
SHA256_HOSTNAME       = 'localhost'
SHA256_PORT           = 25900
SHA256_GROUP_SIZE     = 1000
SHA256_SOCKET_TIMEOUT = 40

###############################################################################

# Generic settings

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
